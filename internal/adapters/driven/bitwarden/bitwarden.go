package bitwarden

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/IbiliAze/vaultlet/internal/domain"
	"github.com/IbiliAze/vaultlet/internal/ports"

	"github.com/bitwarden/sdk-go/v2"
)

type Store struct {
	client      sdk.BitwardenClientInterface
	projectID   string
	orgID       string
	allowWrites bool
}

func New(cfg Config) (*Store, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	client, err := sdk.NewBitwardenClient(optional(cfg.APIURL), optional(cfg.IdentityURL))
	if err != nil {
		return nil, fmt.Errorf("bitwarden: init client: %w", err)
	}

	if err := client.AccessTokenLogin(cfg.AccessToken, nil); err != nil {
		client.Close()
		return nil, fmt.Errorf("bitwarden: access token login: %w", err)
	}

	return &Store{client: client, projectID: cfg.ProjectID, orgID: cfg.OrgID, allowWrites: cfg.AllowWrites}, nil
}

// Close releases the FFI handle held by the underlying Rust client.
func (s *Store) Close() { s.client.Close() }

func (s *Store) Get(ctx context.Context, key domain.Key) (domain.Secret, error) {
	// The SDK calls into the Rust core over cgo and blocks; it takes no
	// context, so the best we can do is refuse work that is already cancelled.
	if err := ctx.Err(); err != nil {
		return domain.Secret{}, err
	}

	id, err := s.resolveID(key)
	if err != nil {
		return domain.Secret{}, err
	}

	res, err := s.client.Secrets().Get(id)
	if err != nil {
		return domain.Secret{}, fmt.Errorf("bitwarden: get secret %s: %w", key, err)
	}

	version, err := versionAt(res.RevisionDate)
	if err != nil {
		return domain.Secret{}, fmt.Errorf("bitwarden: secret %s: %w", key, err)
	}

	return domain.NewSecret(domain.SecretMeta{
		Key:       key,
		Version:   version,
		CreatedAt: res.CreationDate.UTC(),
	}, []byte(res.Value))
}

// resolveID maps a domain key onto the Bitwarden secret UUID. The SDK only
// addresses secrets by UUID, so every lookup by name costs a List of the whole
// organization first.
func (s *Store) resolveID(key domain.Key) (string, error) {
	res, err := s.client.Secrets().List(s.orgID)
	if err != nil {
		return "", fmt.Errorf("bitwarden: list secrets: %w", err)
	}

	name := key.String()
	for _, ident := range res.Data {
		if ident.Key == name && s.inProject(ident.ProjectIDS) {
			return ident.ID, nil
		}
	}
	return "", fmt.Errorf("bitwarden: %s: %w", key, ports.ErrNotFound)
}

// inProject reports whether a secret belongs to the project this Store is
// scoped to. An unset projectID means the whole organization is in scope.
func (s *Store) inProject(projectIDs []string) bool {
	if s.projectID == "" {
		return true
	}
	for _, id := range projectIDs {
		if id == s.projectID {
			return true
		}
	}
	return false
}

func (s *Store) Put(ctx context.Context, key domain.Key, value []byte) (domain.SecretMeta, error) {
	if err := ctx.Err(); err != nil {
		return domain.SecretMeta{}, err
	}

	if !s.allowWrites {
		return domain.SecretMeta{}, fmt.Errorf("bitwarden: %w", ports.ErrReadOnly)

	}

	if len(value) == 0 {
		return domain.SecretMeta{}, fmt.Errorf("bitwarden: %w", domain.ErrEmptyValue)
	}

	projects := []string{}
	if s.projectID != "" {
		projects = []string{s.projectID}
	}

	id, err := s.resolveID(key)
	switch {
	case errors.Is(err, ports.ErrNotFound):
		res, err := s.client.Secrets().Create(key.String(), string(value), "", s.orgID, projects)
		if err != nil {
			return domain.SecretMeta{}, fmt.Errorf("bitwarden: create secret %s: %w", key, err)
		}

		version, err := versionAt(res.RevisionDate)
		if err != nil {
			return domain.SecretMeta{}, fmt.Errorf("bitwarden: secret %s: %w", key, err)
		}
		return domain.SecretMeta{
			Key:       key,
			Version:   version,
			CreatedAt: res.CreationDate.UTC(),
		}, nil
	case err != nil:
		return domain.SecretMeta{}, err
	}

	// Update replaces every field, so the note has to be carried across.
	prev, err := s.client.Secrets().Get(id)
	if err != nil {
		return domain.SecretMeta{}, fmt.Errorf("bitwarden: read secret %s before update: %w", key, err)
	}

	res, err := s.client.Secrets().Update(id, key.String(), string(value), prev.Note, s.orgID, projects)
	if err != nil {
		return domain.SecretMeta{}, fmt.Errorf("bitwarden: update secret %s: %w", key, err)
	}
	version, err := versionAt(res.RevisionDate)
	if err != nil {
		return domain.SecretMeta{}, fmt.Errorf("bitwarden: secret %s: %w", key, err)
	}

	return domain.SecretMeta{
		Key:       key,
		Version:   version,
		CreatedAt: res.CreationDate.UTC()}, nil
}

// List returns metadata for every secret at or beneath ns, sorted by key.
// A zero Namespace lists everything in scope.
//
// This costs two round trips: the identifiers endpoint carries no dates, so the
// UUIDs falling under ns are collected first and their metadata fetched in one
// bulk call. GetByIDS returns secret values too; they are deliberately dropped,
// since SecretMeta exists precisely so callers can list without handling them.
func (s *Store) List(ctx context.Context, ns domain.Namespace) ([]domain.SecretMeta, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	res, err := s.client.Secrets().List(s.orgID)
	if err != nil {
		return nil, fmt.Errorf("bitwarden: list secrets: %w", err)
	}

	ids := make([]string, 0, len(res.Data))
	for _, ident := range res.Data {
		if !s.inProject(ident.ProjectIDS) {
			continue
		}
		// Secrets written outside vaultlet need not follow the key grammar.
		// They are not ours to report, so skip them rather than failing the
		// whole listing on one foreign name.
		key, err := domain.ParseKey(ident.Key)
		if err != nil {
			continue
		}
		if !ns.Contains(key.Namespace()) {
			continue
		}
		ids = append(ids, ident.ID)
	}
	if len(ids) == 0 {
		return nil, nil
	}

	full, err := s.client.Secrets().GetByIDS(ids)
	if err != nil {
		return nil, fmt.Errorf("bitwarden: get secrets by id: %w", err)
	}

	out := make([]domain.SecretMeta, 0, len(full.Data))
	for _, sec := range full.Data {
		key, err := domain.ParseKey(sec.Key)
		if err != nil {
			continue
		}
		version, err := versionAt(sec.RevisionDate)
		if err != nil {
			return nil, fmt.Errorf("bitwarden: secret %s: %w", key, err)
		}
		out = append(out, domain.SecretMeta{
			Key:       key,
			Version:   version,
			CreatedAt: sec.CreationDate.UTC(),
		})
	}

	slices.SortFunc(out, func(a, b domain.SecretMeta) int {
		return strings.Compare(a.Key.String(), b.Key.String())
	})
	return out, nil
}

// versionLayout is RFC 3339 with fixed-width nanoseconds. The stdlib's
// RFC3339Nano strips trailing zeros, which makes versions vary in width and
// sort incorrectly; padding with zeros keeps full precision so two writes in
// the same second stay distinguishable.
const versionLayout = "2006-01-02T15:04:05.000000000Z07:00"

// versionAt derives a domain.Version from a Bitwarden revision date. Bitwarden
// has no version identifier of its own, and RevisionDate is the only field that
// changes on every write. Every method must build versions through here, or
// values from Get and List will not compare equal.
func versionAt(t time.Time) (domain.Version, error) {
	return domain.NewVersion(t.UTC().Format(versionLayout))
}

func (s *Store) Delete(ctx context.Context, key domain.Key) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if !s.allowWrites {
		return fmt.Errorf("bitwarden: %w", ports.ErrReadOnly)
	}

	id, err := s.resolveID(key)
	if err != nil {
		return err
	}

	res, err := s.client.Secrets().Delete([]string{id})
	if err != nil {
		return fmt.Errorf("bitwarden: delete secret %s: %w", key, err)
	}

	for _, d := range res.Data {
		if d.Error != nil {
			return fmt.Errorf("bitwarden: delete secret %s: %s", key, *d.Error)
		}
	}
	return nil
}

func (s *Store) Watch(ctx context.Context, ns domain.Namespace) (<-chan domain.SecretEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c := make(chan domain.SecretEvent)

	return c, nil
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

var _ ports.SecretStore = (*Store)(nil)
