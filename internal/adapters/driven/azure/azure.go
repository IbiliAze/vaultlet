// Package azure implements ports.SecretStore over Azure Key Vault secrets.
//
// Key Vault is a flat namespace of case-insensitive names, so vaultlet keys
// are encoded (see name.go) and namespaces are filtered client-side from a
// full listing. Versions are derived from the secret's Updated timestamp,
// because the listing endpoint returns versionless identifiers and Get and
// List must agree on a version for Watch to diff correctly.
//
// Delete is a soft delete: Key Vault keeps the secret recoverable for its
// retention period and refuses to reuse the name until it is purged.
// Set purge_on_delete to purge immediately after deleting; this requires
// the purge permission and a vault without purge protection.
package azure

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/IbiliAze/vaultlet/internal/adapters/driven/watch"
	"github.com/IbiliAze/vaultlet/internal/domain"
	"github.com/IbiliAze/vaultlet/internal/ports"
)

// api is the slice of *azsecrets.Client the Store uses, so tests can
// substitute an in-memory fake.
type api interface {
	GetSecret(ctx context.Context, name, version string, opts *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
	SetSecret(ctx context.Context, name string, params azsecrets.SetSecretParameters, opts *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error)
	DeleteSecret(ctx context.Context, name string, opts *azsecrets.DeleteSecretOptions) (azsecrets.DeleteSecretResponse, error)
	PurgeDeletedSecret(ctx context.Context, name string, opts *azsecrets.PurgeDeletedSecretOptions) (azsecrets.PurgeDeletedSecretResponse, error)
	NewListSecretPropertiesPager(opts *azsecrets.ListSecretPropertiesOptions) *runtime.Pager[azsecrets.ListSecretPropertiesResponse]
}

type Store struct {
	client        api
	pollInterval  time.Duration
	allowWrites   bool
	purgeOnDelete bool

	// purgeRetry is how long Delete waits between purge attempts while
	// Key Vault is still finishing the soft delete. Shortened in tests.
	purgeRetry time.Duration
}

func New(cfg Config) (*Store, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	var (
		cred azcore.TokenCredential
		err  error
	)
	if cfg.explicitCredentials() {
		cred, err = azidentity.NewClientSecretCredential(cfg.TenantID, cfg.ClientID, cfg.ClientSecret, nil)
	} else {
		cred, err = azidentity.NewDefaultAzureCredential(nil)
	}
	if err != nil {
		return nil, fmt.Errorf("azure: credentials: %w", err)
	}

	client, err := azsecrets.NewClient(cfg.VaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: init client: %w", err)
	}

	return newStore(client, cfg), nil
}

func newStore(client api, cfg Config) *Store {
	return &Store{
		client:        client,
		pollInterval:  cfg.PollInterval,
		allowWrites:   cfg.AllowWrites,
		purgeOnDelete: cfg.PurgeOnDelete,
		purgeRetry:    time.Second,
	}
}

func (s *Store) Get(ctx context.Context, key domain.Key) (domain.Secret, error) {
	name, err := encodeName(key)
	if err != nil {
		return domain.Secret{}, fmt.Errorf("azure: %w", err)
	}

	res, err := s.client.GetSecret(ctx, name, "", nil)
	if err != nil {
		return domain.Secret{}, wrap(err, "get secret %s", key)
	}

	meta, err := metaOf(key, res.Attributes)
	if err != nil {
		return domain.Secret{}, err
	}
	if res.Value == nil {
		return domain.Secret{}, fmt.Errorf("azure: secret %s: %w", key, domain.ErrEmptyValue)
	}
	return domain.NewSecret(meta, []byte(*res.Value))
}

func (s *Store) Put(ctx context.Context, key domain.Key, value []byte) (domain.SecretMeta, error) {
	if !s.allowWrites {
		return domain.SecretMeta{}, fmt.Errorf("azure: %w", ports.ErrReadOnly)
	}
	if len(value) == 0 {
		return domain.SecretMeta{}, fmt.Errorf("azure: %w", domain.ErrEmptyValue)
	}

	name, err := encodeName(key)
	if err != nil {
		return domain.SecretMeta{}, fmt.Errorf("azure: %w", err)
	}

	res, err := s.client.SetSecret(ctx, name, azsecrets.SetSecretParameters{
		Value: ptr(string(value)),
		Tags:  map[string]*string{keyTag: ptr(key.String())},
	}, nil)
	if err != nil {
		if statusCode(err) == http.StatusConflict {
			return domain.SecretMeta{}, fmt.Errorf("azure: put secret %s: name is soft-deleted and not yet purged; recover or purge it in Key Vault, or enable purge_on_delete: %w", key, err)
		}
		return domain.SecretMeta{}, wrap(err, "put secret %s", key)
	}

	return metaOf(key, res.Attributes)
}

// List returns metadata for every vaultlet-encoded secret at or beneath ns,
// sorted by key. Key Vault cannot filter server-side, so this walks the whole
// vault on every call; secrets whose names do not decode (written by hand or
// by another tool) are skipped rather than failing the listing.
func (s *Store) List(ctx context.Context, ns domain.Namespace) ([]domain.SecretMeta, error) {
	var out []domain.SecretMeta

	pager := s.client.NewListSecretPropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrap(err, "list secrets")
		}
		for _, props := range page.Value {
			if props == nil || props.ID == nil {
				continue
			}
			key, err := decodeName(props.ID.Name())
			if err != nil {
				continue
			}
			if !ns.Contains(key.Namespace()) {
				continue
			}
			meta, err := metaOf(key, props.Attributes)
			if err != nil {
				return nil, err
			}
			out = append(out, meta)
		}
	}

	slices.SortFunc(out, func(a, b domain.SecretMeta) int {
		return strings.Compare(a.Key.String(), b.Key.String())
	})
	return out, nil
}

func (s *Store) Delete(ctx context.Context, key domain.Key) error {
	if !s.allowWrites {
		return fmt.Errorf("azure: %w", ports.ErrReadOnly)
	}

	name, err := encodeName(key)
	if err != nil {
		return fmt.Errorf("azure: %w", err)
	}

	if _, err := s.client.DeleteSecret(ctx, name, nil); err != nil {
		return wrap(err, "delete secret %s", key)
	}
	if !s.purgeOnDelete {
		return nil
	}

	// The delete above returns before Key Vault has finished moving the
	// secret into the deleted state, during which purge answers 409.
	// Bounded so a vault that never settles cannot hang the RPC.
	const maxAttempts = 30
	for attempt := 1; ; attempt++ {
		_, err := s.client.PurgeDeletedSecret(ctx, name, nil)
		switch {
		case err == nil, statusCode(err) == http.StatusNotFound:
			return nil
		case statusCode(err) == http.StatusConflict && attempt < maxAttempts:
			select {
			case <-time.After(s.purgeRetry):
			case <-ctx.Done():
				return ctx.Err()
			}
		default:
			return wrap(err, "purge deleted secret %s", key)
		}
	}
}

// Watch polls List; Key Vault's Event Grid notifications would need an
// endpoint of their own and are out of scope for a single-binary server.
func (s *Store) Watch(ctx context.Context, ns domain.Namespace) (<-chan domain.SecretEvent, error) {
	return watch.Poll(ctx, ns, s.pollInterval, s.List)
}

// versionLayout matches the Bitwarden adapter: RFC 3339 with fixed-width
// nanoseconds so versions sort correctly and two writes in the same second
// stay distinguishable. Key Vault has real version identifiers, but the
// listing endpoint does not return them, and Get and List must agree.
const versionLayout = "2006-01-02T15:04:05.000000000Z07:00"

func metaOf(key domain.Key, attrs *azsecrets.SecretAttributes) (domain.SecretMeta, error) {
	if attrs == nil || attrs.Updated == nil || attrs.Created == nil {
		return domain.SecretMeta{}, fmt.Errorf("azure: secret %s: response missing attributes", key)
	}
	version, err := domain.NewVersion(attrs.Updated.UTC().Format(versionLayout))
	if err != nil {
		return domain.SecretMeta{}, fmt.Errorf("azure: secret %s: %w", key, err)
	}
	return domain.SecretMeta{
		Key:       key,
		Version:   version,
		CreatedAt: attrs.Created.UTC(),
	}, nil
}

// wrap prefixes a Key Vault error and maps a 404 onto ports.ErrNotFound so
// callers can use errors.Is across the port boundary. Both the original
// error and the sentinel stay in the chain.
func wrap(err error, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	if statusCode(err) == http.StatusNotFound {
		return fmt.Errorf("azure: %s: %w: %w", msg, ports.ErrNotFound, err)
	}
	return fmt.Errorf("azure: %s: %w", msg, err)
}

func statusCode(err error) int {
	var re *azcore.ResponseError
	if errors.As(err, &re) {
		return re.StatusCode
	}
	return 0
}

func ptr[T any](v T) *T { return &v }

var _ ports.SecretStore = (*Store)(nil)
