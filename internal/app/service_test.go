package app

import (
	"context"
	"errors"
	"maps"
	"slices"
	"testing"

	"github.com/IbiliAze/vaultlet/internal/domain"
	"github.com/IbiliAze/vaultlet/internal/ports"
)

// fakeStore is an in-memory ports.SecretStore. It records calls so a test
// can assert the service never touched it on a denied request.
type fakeStore struct {
	secrets     map[string]domain.Secret // keyed by key.String()
	err         error                    // if set, every method returns it
	getCalls    int
	listCalls   int
	putCalls    int
	deleteCalls int
	watchCalls  int
}

func (f *fakeStore) Get(_ context.Context, key domain.Key) (domain.Secret, error) {
	f.getCalls++
	if f.err != nil {
		return domain.Secret{}, f.err
	}
	s, ok := f.secrets[key.String()]
	if !ok {
		return domain.Secret{}, ports.ErrNotFound
	}
	return s, nil
}

func (f *fakeStore) Put(_ context.Context, key domain.Key, value []byte) (domain.SecretMeta, error) {
	f.putCalls++
	if f.err != nil {
		return domain.SecretMeta{}, f.err
	}
	return domain.SecretMeta{Key: key}, nil
}
func (f *fakeStore) List(_ context.Context, ns domain.Namespace) ([]domain.SecretMeta, error) {
	f.listCalls++
	if f.err != nil {
		return nil, f.err
	}
	var out []domain.SecretMeta
	for _, s := range f.secrets {
		if ns.Contains(s.Key().Namespace()) {
			out = append(out, s.Meta())
		}
	}
	return out, nil
}

func (f *fakeStore) Delete(_ context.Context, key domain.Key) error {
	f.deleteCalls++
	if f.err != nil {
		return f.err
	}
	if _, ok := f.secrets[key.String()]; !ok {
		return ports.ErrNotFound
	}
	delete(f.secrets, key.String())
	return nil
}

func (f *fakeStore) Watch(ctx context.Context, ns domain.Namespace) (<-chan domain.SecretEvent, error) {
	f.watchCalls++
	if f.err != nil {
		return nil, f.err
	}
	c := make(chan domain.SecretEvent)
	close(c)
	return c, nil
}

func TestServiceList(t *testing.T) {
	// Three secrets across three namespaces so the filter loop has
	// something to keep and something to drop.
	seed := seedSecrets(t,
		"payments/prod/A",
		"payments/dev/B",
		"billing/C",
	)

	alice := WithPrincipal(context.Background(), "alice")

	tests := []struct {
		name       string
		ctx        context.Context
		rule       string // namespace alice may list; "" means no rule
		list       string // namespace requested
		storeErr   error
		wantErr    error
		wantCalled bool
		wantKeys   []string
	}{
		{
			name: "no principal", ctx: context.Background(),
			rule: "payments", list: "payments",
			wantErr: ErrPermissionDenied,
		},
		{
			name: "no rule for principal", ctx: alice,
			rule: "", list: "payments",
			wantErr: ErrPermissionDenied,
		},
		{
			name: "namespace outside rule", ctx: alice,
			rule: "payments", list: "billing",
			wantErr: ErrPermissionDenied,
		},
		{
			name: "rule covers request", ctx: alice,
			rule: "payments", list: "payments",
			wantCalled: true, wantKeys: []string{"payments/dev/B", "payments/prod/A"},
		},
		{
			name: "request narrower than rule", ctx: alice,
			rule: "payments", list: "payments/prod",
			wantCalled: true, wantKeys: []string{"payments/prod/A"},
		},
		{
			// canList lets a broad request through when a rule sits inside
			// it, but the per-key filter must still hide the rest.
			name: "request broader than rule", ctx: alice,
			rule: "payments/prod", list: "payments",
			wantCalled: true, wantKeys: []string{"payments/prod/A"},
		},
		{
			name: "store error passes through", ctx: alice,
			rule: "payments", list: "payments",
			storeErr: ports.ErrReadOnly, wantErr: ports.ErrReadOnly,
			wantCalled: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var specs []RuleSpec
			if tc.rule != "" {
				specs = append(specs, RuleSpec{Principal: "alice", Namespace: tc.rule, Actions: []string{"list"}})
			}
			policy, err := NewPolicy(specs)
			if err != nil {
				t.Fatal(err)
			}

			store := &fakeStore{secrets: maps.Clone(seed), err: tc.storeErr}
			svc := NewService(store, policy)

			got, err := svc.List(tc.ctx, domain.MustNamespace(tc.list))

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if called := store.listCalls > 0; called != tc.wantCalled {
				t.Errorf("store called = %v, want %v", called, tc.wantCalled)
			}

			gotKeys := make([]string, 0, len(got))
			for _, m := range got {
				gotKeys = append(gotKeys, m.Key.String())
			}
			slices.Sort(gotKeys)
			if !slices.Equal(gotKeys, tc.wantKeys) {
				t.Errorf("keys = %v, want %v", gotKeys, tc.wantKeys)
			}
		})
	}
}

// seedSecrets builds a store map with one placeholder secret per key.
func seedSecrets(t *testing.T, keys ...string) map[string]domain.Secret {
	t.Helper()
	out := make(map[string]domain.Secret, len(keys))
	for _, k := range keys {
		s, err := domain.NewSecret(domain.SecretMeta{
			Key:     domain.MustKey(k),
			Version: mustVersion(t, "v1"),
		}, []byte("value"))
		if err != nil {
			t.Fatal(err)
		}
		out[k] = s
	}
	return out
}

func TestServiceDelete(t *testing.T) {
	key := domain.MustKey("payments/prod/DB_URL")

	secret, err := domain.NewSecret(domain.SecretMeta{
		Key:     key,
		Version: mustVersion(t, "v1"),
	}, []byte("postgres://..."))
	if err != nil {
		t.Fatal(err)
	}

	policy, err := NewPolicy([]RuleSpec{
		{Principal: "alice", Namespace: "payments", Actions: []string{"delete"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		ctx        context.Context
		storeErr   error
		wantErr    error
		wantCalled bool
	}{
		{"no principal", context.Background(), nil, ErrPermissionDenied, false},
		{"wrong principal", WithPrincipal(context.Background(), "bob"), nil, ErrPermissionDenied, false},
		{"allowed", WithPrincipal(context.Background(), "alice"), nil, nil, true},
		{"missing key", WithPrincipal(context.Background(), "alice"), nil, ports.ErrNotFound, true},
		{"secret is read-only", WithPrincipal(context.Background(), "alice"), ports.ErrReadOnly, ports.ErrReadOnly, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeStore{
				secrets: map[string]domain.Secret{},
				err:     tc.storeErr,
			}
			// Seed the secret except when the case wants the store's own
			// not-found path, so that branch is exercised for real.
			if !errors.Is(tc.wantErr, ports.ErrNotFound) {
				store.secrets[key.String()] = secret
			}
			svc := NewService(store, policy)

			err := svc.Delete(tc.ctx, key)

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if called := store.deleteCalls > 0; called != tc.wantCalled {
				t.Errorf("store called = %v, want %v", called, tc.wantCalled)
			}
			if _, still := store.secrets[key.String()]; tc.wantErr == nil && still {
				t.Errorf("secret still present in store after successful delete")
			}
		})
	}
}

func TestServicePut(t *testing.T) {
	key := domain.MustKey("payments/prod/DB_URL")

	policy, err := NewPolicy([]RuleSpec{
		{Principal: "alice", Namespace: "payments", Actions: []string{"put"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	value := []byte("secret")

	tests := []struct {
		name       string
		ctx        context.Context
		storeErr   error
		wantErr    error
		wantCalled bool
	}{
		{"no principal", context.Background(), nil, ErrPermissionDenied, false},
		{"wrong principal", WithPrincipal(context.Background(), "bob"), nil, ErrPermissionDenied, false},
		{"allowed", WithPrincipal(context.Background(), "alice"), nil, nil, true},
		{"secret is read-only", WithPrincipal(context.Background(), "alice"), ports.ErrReadOnly, ports.ErrReadOnly, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeStore{
				secrets: map[string]domain.Secret{},
				err:     tc.storeErr,
			}
			svc := NewService(store, policy)

			got, err := svc.Put(tc.ctx, key, value)

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if called := store.putCalls > 0; called != tc.wantCalled {
				t.Errorf("store called = %v, want %v", called, tc.wantCalled)
			}
			if tc.wantErr == nil && got.Key.String() != "payments/prod/DB_URL" {
				t.Errorf("value = %q, want the key", got.Key.String())
			}
		})
	}
}

func TestServiceGet(t *testing.T) {
	key := domain.MustKey("payments/prod/DB_URL")
	secret, err := domain.NewSecret(domain.SecretMeta{
		Key:     key,
		Version: mustVersion(t, "v1"),
	}, []byte("postgres://..."))
	if err != nil {
		t.Fatal(err)
	}

	policy, err := NewPolicy([]RuleSpec{
		{Principal: "alice", Namespace: "payments", Actions: []string{"get"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		ctx        context.Context
		storeErr   error
		wantErr    error
		wantCalled bool
	}{
		{"no principal", context.Background(), nil, ErrPermissionDenied, false},
		{"wrong principal", WithPrincipal(context.Background(), "bob"), nil, ErrPermissionDenied, false},
		{"allowed", WithPrincipal(context.Background(), "alice"), nil, nil, true},
		{"store error passes through", WithPrincipal(context.Background(), "alice"), ports.ErrNotFound, ports.ErrNotFound, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeStore{
				secrets: map[string]domain.Secret{key.String(): secret},
				err:     tc.storeErr,
			}
			svc := NewService(store, policy)

			got, err := svc.Get(tc.ctx, key)

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if called := store.getCalls > 0; called != tc.wantCalled {
				t.Errorf("store called = %v, want %v", called, tc.wantCalled)
			}
			if tc.wantErr == nil && string(got.Value()) != "postgres://..." {
				t.Errorf("value = %q, want the stored secret", got.Value())
			}
		})
	}
}

func mustVersion(t *testing.T, id string) domain.Version {
	t.Helper()
	v, err := domain.NewVersion(id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

var _ ports.SecretStore = (*fakeStore)(nil)
