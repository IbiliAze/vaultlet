package azure

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/IbiliAze/vaultlet/internal/domain"
	"github.com/IbiliAze/vaultlet/internal/ports"
)

// fakeVault is an in-memory Key Vault that mimics the parts of the REST
// behaviour the Store depends on: 404 for unknown names, soft delete with a
// purge that answers 409 until the delete "settles", and paged listing.
type fakeVault struct {
	mu      sync.Mutex // the real client is goroutine-safe; Watch polls concurrently
	secrets map[string]*azsecrets.Secret
	deleted map[string]int // name -> purge attempts still to reject with 409
	now     time.Time

	err      error // if set, every call fails with it
	pageSize int
	purges   int
}

func newFakeVault() *fakeVault {
	return &fakeVault{
		secrets:  map[string]*azsecrets.Secret{},
		deleted:  map[string]int{},
		now:      time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC),
		pageSize: 2,
	}
}

func azErr(status int) error {
	return &azcore.ResponseError{
		StatusCode:  status,
		RawResponse: &http.Response{StatusCode: status, Request: &http.Request{Method: "GET"}},
	}
}

func (f *fakeVault) tick() time.Time {
	f.now = f.now.Add(time.Second)
	return f.now
}

func (f *fakeVault) GetSecret(_ context.Context, name, _ string, _ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return azsecrets.GetSecretResponse{}, f.err
	}
	s, ok := f.secrets[name]
	if !ok {
		return azsecrets.GetSecretResponse{}, azErr(http.StatusNotFound)
	}
	return azsecrets.GetSecretResponse{Secret: *s}, nil
}

func (f *fakeVault) SetSecret(_ context.Context, name string, p azsecrets.SetSecretParameters, _ *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return azsecrets.SetSecretResponse{}, f.err
	}
	if _, gone := f.deleted[name]; gone {
		return azsecrets.SetSecretResponse{}, azErr(http.StatusConflict)
	}
	now := f.tick()
	created := now
	if prev, ok := f.secrets[name]; ok {
		created = *prev.Attributes.Created
	}
	id := azsecrets.ID("https://v.vault.azure.net/secrets/" + name + "/v1")
	s := &azsecrets.Secret{
		ID:         &id,
		Value:      p.Value,
		Tags:       p.Tags,
		Attributes: &azsecrets.SecretAttributes{Created: &created, Updated: &now},
	}
	f.secrets[name] = s
	return azsecrets.SetSecretResponse{Secret: *s}, nil
}

func (f *fakeVault) DeleteSecret(_ context.Context, name string, _ *azsecrets.DeleteSecretOptions) (azsecrets.DeleteSecretResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return azsecrets.DeleteSecretResponse{}, f.err
	}
	if _, ok := f.secrets[name]; !ok {
		return azsecrets.DeleteSecretResponse{}, azErr(http.StatusNotFound)
	}
	delete(f.secrets, name)
	f.deleted[name] = 2 // two purge attempts see 409 before it settles
	return azsecrets.DeleteSecretResponse{}, nil
}

func (f *fakeVault) PurgeDeletedSecret(_ context.Context, name string, _ *azsecrets.PurgeDeletedSecretOptions) (azsecrets.PurgeDeletedSecretResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.purges++
	pending, ok := f.deleted[name]
	if !ok {
		return azsecrets.PurgeDeletedSecretResponse{}, azErr(http.StatusNotFound)
	}
	if pending > 0 {
		f.deleted[name] = pending - 1
		return azsecrets.PurgeDeletedSecretResponse{}, azErr(http.StatusConflict)
	}
	delete(f.deleted, name)
	return azsecrets.PurgeDeletedSecretResponse{}, nil
}

func (f *fakeVault) NewListSecretPropertiesPager(_ *azsecrets.ListSecretPropertiesOptions) *runtime.Pager[azsecrets.ListSecretPropertiesResponse] {
	// Sorted names keep pages stable; pageSize entries are served at a
	// time with a NextLink that is just the offset of the next page.
	return runtime.NewPager(runtime.PagingHandler[azsecrets.ListSecretPropertiesResponse]{
		More: func(r azsecrets.ListSecretPropertiesResponse) bool { return r.NextLink != nil },
		Fetcher: func(_ context.Context, cur *azsecrets.ListSecretPropertiesResponse) (azsecrets.ListSecretPropertiesResponse, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.err != nil {
				return azsecrets.ListSecretPropertiesResponse{}, f.err
			}
			names := make([]string, 0, len(f.secrets))
			for n := range f.secrets {
				names = append(names, n)
			}
			sortStrings(names)
			start := 0
			if cur != nil && cur.NextLink != nil {
				start = int((*cur.NextLink)[0] - '0')
			}
			end := min(start+f.pageSize, len(names))
			var resp azsecrets.ListSecretPropertiesResponse
			for _, n := range names[start:end] {
				s := f.secrets[n]
				id := azsecrets.ID("https://v.vault.azure.net/secrets/" + n)
				resp.Value = append(resp.Value, &azsecrets.SecretProperties{ID: &id, Attributes: s.Attributes, Tags: s.Tags})
			}
			if end < len(names) {
				resp.NextLink = ptr(string(rune('0' + end)))
			}
			return resp, nil
		},
	})
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func testStore(t *testing.T, vault *fakeVault, writes bool) *Store {
	t.Helper()
	s := newStore(vault, Config{PollInterval: time.Second, AllowWrites: writes, PurgeOnDelete: true})
	s.purgeRetry = time.Millisecond
	return s
}

func TestPutGetRoundTrip(t *testing.T) {
	vault := newFakeVault()
	s := testStore(t, vault, true)
	ctx := context.Background()
	key := domain.MustKey("payments/prod/DB_URL")

	meta, err := s.Put(ctx, key, []byte("postgres://one"))
	if err != nil {
		t.Fatal(err)
	}
	if meta.Key.String() != key.String() || meta.Version.IsZero() || meta.CreatedAt.IsZero() {
		t.Fatalf("meta = %+v, want key, version and created set", meta)
	}

	// The vault holds the encoded name, and the canonical key in a tag.
	stored, ok := vault.secrets["payments-1prod-1-d-b-2-u-r-l"]
	if !ok {
		t.Fatalf("secret not stored under the encoded name; have %v", keys(vault.secrets))
	}
	if got := *stored.Tags[keyTag]; got != key.String() {
		t.Errorf("tag %s = %q, want %q", keyTag, got, key)
	}

	got, err := s.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Value()) != "postgres://one" {
		t.Errorf("value = %q", got.Value())
	}
	if got.Version() != meta.Version {
		t.Errorf("Get version %s != Put version %s", got.Version(), meta.Version)
	}

	// Overwriting yields a new version and keeps the creation time.
	meta2, err := s.Put(ctx, key, []byte("postgres://two"))
	if err != nil {
		t.Fatal(err)
	}
	if meta2.Version == meta.Version {
		t.Error("version unchanged after overwrite")
	}
	if !meta2.CreatedAt.Equal(meta.CreatedAt) {
		t.Errorf("CreatedAt changed on overwrite: %s -> %s", meta.CreatedAt, meta2.CreatedAt)
	}
}

func TestGetNotFound(t *testing.T) {
	s := testStore(t, newFakeVault(), false)
	_, err := s.Get(context.Background(), domain.MustKey("payments/prod/MISSING"))
	if !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	var re *azcore.ResponseError
	if !errors.As(err, &re) {
		t.Error("vendor error dropped from the chain")
	}
}

func TestWriteGuards(t *testing.T) {
	ctx := context.Background()
	key := domain.MustKey("payments/prod/X")

	ro := testStore(t, newFakeVault(), false)
	if _, err := ro.Put(ctx, key, []byte("v")); !errors.Is(err, ports.ErrReadOnly) {
		t.Errorf("Put on read-only: err = %v, want ErrReadOnly", err)
	}
	if err := ro.Delete(ctx, key); !errors.Is(err, ports.ErrReadOnly) {
		t.Errorf("Delete on read-only: err = %v, want ErrReadOnly", err)
	}

	rw := testStore(t, newFakeVault(), true)
	if _, err := rw.Put(ctx, key, nil); !errors.Is(err, domain.ErrEmptyValue) {
		t.Errorf("Put empty: err = %v, want ErrEmptyValue", err)
	}
	if err := rw.Delete(ctx, key); !errors.Is(err, ports.ErrNotFound) {
		t.Errorf("Delete missing: err = %v, want ErrNotFound", err)
	}
}

func TestListFiltersAndPages(t *testing.T) {
	vault := newFakeVault()
	s := testStore(t, vault, true)
	ctx := context.Background()

	for _, k := range []string{"payments/prod/A", "payments/dev/B", "payments/prod/C", "billing/D", "payments/prod/E"} {
		if _, err := s.Put(ctx, domain.MustKey(k), []byte("v")); err != nil {
			t.Fatal(err)
		}
	}
	// A hand-written secret that does not follow the encoding is skipped.
	vault.secrets["Some-Portal-Secret"] = vault.secrets["billing-1-d"]

	metas, err := s.List(ctx, domain.MustNamespace("payments"))
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(metas))
	for _, m := range metas {
		got = append(got, m.Key.String())
	}
	want := []string{"payments/dev/B", "payments/prod/A", "payments/prod/C", "payments/prod/E"}
	if len(got) != len(want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("keys = %v, want %v", got, want)
		}
	}

	// Six stored names at two per page: the walk must cross page breaks.
	if vault.pageSize >= len(vault.secrets) {
		t.Fatal("test no longer exercises paging")
	}
}

func TestDeletePurges(t *testing.T) {
	vault := newFakeVault()
	s := testStore(t, vault, true)
	ctx := context.Background()
	key := domain.MustKey("payments/prod/A")

	if _, err := s.Put(ctx, key, []byte("v")); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if vault.purges != 3 {
		t.Errorf("purge attempts = %d, want 3 (two 409s then success)", vault.purges)
	}
	if len(vault.deleted) != 0 {
		t.Errorf("secret still soft-deleted after purge: %v", keys(vault.deleted))
	}

	// The name is reusable straight away.
	if _, err := s.Put(ctx, key, []byte("again")); err != nil {
		t.Fatalf("Put after purge: %v", err)
	}
}

func TestPutOnSoftDeletedName(t *testing.T) {
	vault := newFakeVault()
	s := testStore(t, vault, true)
	s.purgeOnDelete = false
	ctx := context.Background()
	key := domain.MustKey("payments/prod/A")

	if _, err := s.Put(ctx, key, []byte("v")); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if vault.purges != 0 {
		t.Errorf("purged %d times with purge_on_delete off", vault.purges)
	}
	_, err := s.Put(ctx, key, []byte("again"))
	if err == nil || statusCode(err) != http.StatusConflict {
		t.Fatalf("Put on soft-deleted name: err = %v, want a 409 with guidance", err)
	}
}

func TestWatchEmitsSnapshotAndChanges(t *testing.T) {
	vault := newFakeVault()
	s := testStore(t, vault, true)
	s.pollInterval = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	key := domain.MustKey("payments/prod/A")
	if _, err := s.Put(ctx, key, []byte("v1")); err != nil {
		t.Fatal(err)
	}

	events, err := s.Watch(ctx, domain.MustNamespace("payments"))
	if err != nil {
		t.Fatal(err)
	}
	next := func(want domain.Type) {
		t.Helper()
		select {
		case ev := <-events:
			if ev.Type != want {
				t.Fatalf("event = %s %q, want %s", ev.Type, ev.Meta.Key, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for %s", want)
		}
	}
	next(domain.Added)
	next(domain.InSync)

	if _, err := s.Put(ctx, key, []byte("v2")); err != nil {
		t.Fatal(err)
	}
	next(domain.Updated)

	if err := s.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	next(domain.Deleted)
}

func TestConfigValidate(t *testing.T) {
	good := Config{VaultURL: "https://v.vault.azure.net", PollInterval: 30 * time.Second}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	bad := []Config{
		{PollInterval: 30 * time.Second},
		{VaultURL: "http://v.vault.azure.net", PollInterval: 30 * time.Second},
		{VaultURL: "v.vault.azure.net", PollInterval: 30 * time.Second},
		{VaultURL: "https://v.vault.azure.net"},
		{VaultURL: "https://v.vault.azure.net", PollInterval: 100 * time.Millisecond},
		{VaultURL: "https://v.vault.azure.net", PollInterval: 30 * time.Second, TenantID: "t"},
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("config %d accepted: %+v", i, c)
		}
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
