// Package gcp implements ports.SecretStore over Google Cloud Secret Manager.
//
// One vaultlet key maps to one Secret Manager secret; each Put adds a new
// version and reads access "latest". Secret IDs are case-sensitive and allow
// [A-Za-z0-9_-], so keys are lightly escaped (see name.go). Versions are
// Secret Manager's own numeric version IDs, so Get, Put and List agree
// without any timestamp derivation.
//
// Secret Manager has no server-side prefix filter that matches the key
// grammar, so List walks the project and filters client-side. It then needs
// one GetSecretVersion per matching secret to learn the current version,
// which is what Watch diffs on; on a large project that is the cost to
// watch for.
//
// Delete is permanent: it removes the secret and every version.
package gcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"slices"
	"strings"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	pb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/IbiliAze/vaultlet/internal/adapters/driven/watch"
	"github.com/IbiliAze/vaultlet/internal/domain"
	"github.com/IbiliAze/vaultlet/internal/ports"
)

// api is the slice of *secretmanager.Client the Store uses, with the
// iterator flattened so tests can substitute an in-memory fake.
type api interface {
	GetSecret(context.Context, *pb.GetSecretRequest) (*pb.Secret, error)
	CreateSecret(context.Context, *pb.CreateSecretRequest) (*pb.Secret, error)
	AddSecretVersion(context.Context, *pb.AddSecretVersionRequest) (*pb.SecretVersion, error)
	GetSecretVersion(context.Context, *pb.GetSecretVersionRequest) (*pb.SecretVersion, error)
	AccessSecretVersion(context.Context, *pb.AccessSecretVersionRequest) (*pb.AccessSecretVersionResponse, error)
	DeleteSecret(context.Context, *pb.DeleteSecretRequest) error
	ListSecrets(context.Context, *pb.ListSecretsRequest) ([]*pb.Secret, error)
	Close() error
}

// sdkClient adapts the generated client to api: it drops the gax call
// options and drains ListSecrets' iterator.
type sdkClient struct{ c *secretmanager.Client }

func (s sdkClient) GetSecret(ctx context.Context, r *pb.GetSecretRequest) (*pb.Secret, error) {
	return s.c.GetSecret(ctx, r)
}
func (s sdkClient) CreateSecret(ctx context.Context, r *pb.CreateSecretRequest) (*pb.Secret, error) {
	return s.c.CreateSecret(ctx, r)
}
func (s sdkClient) AddSecretVersion(ctx context.Context, r *pb.AddSecretVersionRequest) (*pb.SecretVersion, error) {
	return s.c.AddSecretVersion(ctx, r)
}
func (s sdkClient) GetSecretVersion(ctx context.Context, r *pb.GetSecretVersionRequest) (*pb.SecretVersion, error) {
	return s.c.GetSecretVersion(ctx, r)
}
func (s sdkClient) AccessSecretVersion(ctx context.Context, r *pb.AccessSecretVersionRequest) (*pb.AccessSecretVersionResponse, error) {
	return s.c.AccessSecretVersion(ctx, r)
}
func (s sdkClient) DeleteSecret(ctx context.Context, r *pb.DeleteSecretRequest) error {
	return s.c.DeleteSecret(ctx, r)
}
func (s sdkClient) ListSecrets(ctx context.Context, r *pb.ListSecretsRequest) ([]*pb.Secret, error) {
	var out []*pb.Secret
	it := s.c.ListSecrets(ctx, r)
	for {
		sec, err := it.Next()
		if errors.Is(err, iterator.Done) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, sec)
	}
}
func (s sdkClient) Close() error { return s.c.Close() }

type Store struct {
	client       api
	parent       string // projects/<id>
	pollInterval time.Duration
	allowWrites  bool
}

func New(ctx context.Context, cfg Config) (*Store, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	var opts []option.ClientOption
	if cfg.CredentialsFile != "" {
		opts = append(opts, option.WithCredentialsFile(cfg.CredentialsFile))
	}
	client, err := secretmanager.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("gcp: init client: %w", err)
	}
	return newStore(sdkClient{client}, cfg), nil
}

func newStore(client api, cfg Config) *Store {
	return &Store{
		client:       client,
		parent:       "projects/" + cfg.ProjectID,
		pollInterval: cfg.PollInterval,
		allowWrites:  cfg.AllowWrites,
	}
}

// Close releases the client's connections. The composition root probes for
// a bare Close(), so the error can only be logged.
func (s *Store) Close() {
	if err := s.client.Close(); err != nil {
		slog.Warn("gcp: close client", "err", err)
	}
}

func (s *Store) secretName(id string) string { return s.parent + "/secrets/" + id }

func (s *Store) Get(ctx context.Context, key domain.Key) (domain.Secret, error) {
	id, err := encodeID(key)
	if err != nil {
		return domain.Secret{}, fmt.Errorf("gcp: %w", err)
	}

	res, err := s.client.AccessSecretVersion(ctx, &pb.AccessSecretVersionRequest{
		Name: s.secretName(id) + "/versions/latest",
	})
	if err != nil {
		return domain.Secret{}, wrap(err, "get secret %s", key)
	}
	if res.GetPayload() == nil || len(res.GetPayload().GetData()) == 0 {
		return domain.Secret{}, fmt.Errorf("gcp: secret %s: %w", key, domain.ErrEmptyValue)
	}

	// Access carries no timestamps; the secret's create time is on the
	// parent resource.
	sec, err := s.client.GetSecret(ctx, &pb.GetSecretRequest{Name: s.secretName(id)})
	if err != nil {
		return domain.Secret{}, wrap(err, "get secret %s", key)
	}

	meta, err := metaOf(key, res.GetName(), sec)
	if err != nil {
		return domain.Secret{}, err
	}
	return domain.NewSecret(meta, res.GetPayload().GetData())
}

func (s *Store) Put(ctx context.Context, key domain.Key, value []byte) (domain.SecretMeta, error) {
	if !s.allowWrites {
		return domain.SecretMeta{}, fmt.Errorf("gcp: %w", ports.ErrReadOnly)
	}
	if len(value) == 0 {
		return domain.SecretMeta{}, fmt.Errorf("gcp: %w", domain.ErrEmptyValue)
	}

	id, err := encodeID(key)
	if err != nil {
		return domain.SecretMeta{}, fmt.Errorf("gcp: %w", err)
	}

	sec, err := s.client.GetSecret(ctx, &pb.GetSecretRequest{Name: s.secretName(id)})
	switch {
	case code(err) == codes.NotFound:
		sec, err = s.client.CreateSecret(ctx, &pb.CreateSecretRequest{
			Parent:   s.parent,
			SecretId: id,
			Secret: &pb.Secret{
				Replication: &pb.Replication{
					Replication: &pb.Replication_Automatic_{Automatic: &pb.Replication_Automatic{}},
				},
				Annotations: map[string]string{keyAnnotation: key.String()},
			},
		})
		// A concurrent writer may have created it between the two calls;
		// the version add below still succeeds against their secret.
		if code(err) == codes.AlreadyExists {
			sec, err = s.client.GetSecret(ctx, &pb.GetSecretRequest{Name: s.secretName(id)})
		}
		if err != nil {
			return domain.SecretMeta{}, wrap(err, "create secret %s", key)
		}
	case err != nil:
		return domain.SecretMeta{}, wrap(err, "put secret %s", key)
	}

	ver, err := s.client.AddSecretVersion(ctx, &pb.AddSecretVersionRequest{
		Parent:  s.secretName(id),
		Payload: &pb.SecretPayload{Data: value},
	})
	if err != nil {
		return domain.SecretMeta{}, wrap(err, "put secret %s", key)
	}
	return metaOf(key, ver.GetName(), sec)
}

// List returns metadata for every vaultlet-encoded secret at or beneath ns,
// sorted by key. A secret with no accessible latest version (created but
// never written, or its newest version disabled or destroyed) is skipped,
// matching what Get would report for it.
func (s *Store) List(ctx context.Context, ns domain.Namespace) ([]domain.SecretMeta, error) {
	secrets, err := s.client.ListSecrets(ctx, &pb.ListSecretsRequest{Parent: s.parent})
	if err != nil {
		return nil, wrap(err, "list secrets")
	}

	var out []domain.SecretMeta
	for _, sec := range secrets {
		key, err := decodeID(path.Base(sec.GetName()))
		if err != nil {
			continue
		}
		if !ns.Contains(key.Namespace()) {
			continue
		}

		ver, err := s.client.GetSecretVersion(ctx, &pb.GetSecretVersionRequest{
			Name: sec.GetName() + "/versions/latest",
		})
		switch code(err) {
		case codes.OK:
		case codes.NotFound, codes.FailedPrecondition:
			continue
		default:
			return nil, wrap(err, "get latest version of %s", key)
		}
		if ver.GetState() != pb.SecretVersion_ENABLED {
			continue
		}

		meta, err := metaOf(key, ver.GetName(), sec)
		if err != nil {
			return nil, err
		}
		out = append(out, meta)
	}

	slices.SortFunc(out, func(a, b domain.SecretMeta) int {
		return strings.Compare(a.Key.String(), b.Key.String())
	})
	return out, nil
}

func (s *Store) Delete(ctx context.Context, key domain.Key) error {
	if !s.allowWrites {
		return fmt.Errorf("gcp: %w", ports.ErrReadOnly)
	}

	id, err := encodeID(key)
	if err != nil {
		return fmt.Errorf("gcp: %w", err)
	}

	if err := s.client.DeleteSecret(ctx, &pb.DeleteSecretRequest{Name: s.secretName(id)}); err != nil {
		return wrap(err, "delete secret %s", key)
	}
	return nil
}

// Watch polls List. Secret Manager can publish to Pub/Sub topics, but
// consuming those needs infrastructure of its own; polling keeps the
// backend self-contained.
func (s *Store) Watch(ctx context.Context, ns domain.Namespace) (<-chan domain.SecretEvent, error) {
	return watch.Poll(ctx, ns, s.pollInterval, s.List)
}

// metaOf builds metadata from a version resource name (…/versions/N) and
// the parent secret. The version ID is Secret Manager's own, so it is
// identical wherever it is observed.
func metaOf(key domain.Key, versionName string, sec *pb.Secret) (domain.SecretMeta, error) {
	version, err := domain.NewVersion(path.Base(versionName))
	if err != nil {
		return domain.SecretMeta{}, fmt.Errorf("gcp: secret %s: version %q: %w", key, versionName, err)
	}
	if sec.GetCreateTime() == nil {
		return domain.SecretMeta{}, fmt.Errorf("gcp: secret %s: response missing create time", key)
	}
	return domain.SecretMeta{
		Key:       key,
		Version:   version,
		CreatedAt: sec.GetCreateTime().AsTime().UTC(),
	}, nil
}

// wrap prefixes a Secret Manager error and maps NotFound onto
// ports.ErrNotFound so callers can use errors.Is across the port boundary.
// The gRPC status stays in the chain.
func wrap(err error, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	if code(err) == codes.NotFound {
		return fmt.Errorf("gcp: %s: %w: %w", msg, ports.ErrNotFound, err)
	}
	return fmt.Errorf("gcp: %s: %w", msg, err)
}

func code(err error) codes.Code { return status.Code(err) }

var _ ports.SecretStore = (*Store)(nil)
