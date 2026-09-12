package gcp

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	pb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/IbiliAze/vaultlet/internal/domain"
	"github.com/IbiliAze/vaultlet/internal/ports"
)

// fakeProject is an in-memory Secret Manager project: secrets hold numbered
// versions, "latest" resolves to the newest, and every method answers with
// the gRPC status codes the real service uses.
type fakeProject struct {
	mu      sync.Mutex // the real client is goroutine-safe; Watch polls concurrently
	secrets map[string]*fakeSecret
	now     time.Time
	err     error // if set, every call fails with it
	closed  bool
}

type fakeSecret struct {
	secret   *pb.Secret
	versions [][]byte // index+1 is the version number
	disabled map[int]bool
}

func newFakeProject() *fakeProject {
	return &fakeProject{
		secrets: map[string]*fakeSecret{},
		now:     time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC),
	}
}

func (f *fakeProject) lookup(name string) (*fakeSecret, error) {
	if f.err != nil {
		return nil, f.err
	}
	s, ok := f.secrets[name]
	if !ok {
		return nil, status.Error(codes.NotFound, "secret not found")
	}
	return s, nil
}

func (f *fakeProject) GetSecret(_ context.Context, r *pb.GetSecretRequest) (*pb.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, err := f.lookup(r.GetName())
	if err != nil {
		return nil, err
	}
	return s.secret, nil
}

func (f *fakeProject) CreateSecret(_ context.Context, r *pb.CreateSecretRequest) (*pb.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	name := r.GetParent() + "/secrets/" + r.GetSecretId()
	if _, ok := f.secrets[name]; ok {
		return nil, status.Error(codes.AlreadyExists, "exists")
	}
	f.now = f.now.Add(time.Second)
	sec := &pb.Secret{
		Name:        name,
		CreateTime:  timestamppb.New(f.now),
		Annotations: r.GetSecret().GetAnnotations(),
		Replication: r.GetSecret().GetReplication(),
	}
	f.secrets[name] = &fakeSecret{secret: sec, disabled: map[int]bool{}}
	return sec, nil
}

func (f *fakeProject) AddSecretVersion(_ context.Context, r *pb.AddSecretVersionRequest) (*pb.SecretVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, err := f.lookup(r.GetParent())
	if err != nil {
		return nil, err
	}
	s.versions = append(s.versions, r.GetPayload().GetData())
	return f.version(r.GetParent(), s, len(s.versions)), nil
}

func (f *fakeProject) version(name string, s *fakeSecret, n int) *pb.SecretVersion {
	state := pb.SecretVersion_ENABLED
	if s.disabled[n] {
		state = pb.SecretVersion_DISABLED
	}
	return &pb.SecretVersion{
		Name:       fmt.Sprintf("%s/versions/%d", name, n),
		State:      state,
		CreateTime: timestamppb.New(f.now),
	}
}

// resolve turns ".../versions/latest" or ".../versions/N" into the secret
// and version number, with NotFound when there are no versions at all.
func (f *fakeProject) resolve(name string) (*fakeSecret, string, int, error) {
	i := len(name) - len("/versions/")
	for i > 0 && name[i:i+len("/versions/")] != "/versions/" {
		i--
	}
	secretName, ver := name[:i], name[i+len("/versions/"):]
	s, err := f.lookup(secretName)
	if err != nil {
		return nil, "", 0, err
	}
	n := len(s.versions)
	if ver != "latest" {
		fmt.Sscanf(ver, "%d", &n)
	}
	if n == 0 || n > len(s.versions) {
		return nil, "", 0, status.Error(codes.NotFound, "version not found")
	}
	return s, secretName, n, nil
}

func (f *fakeProject) GetSecretVersion(_ context.Context, r *pb.GetSecretVersionRequest) (*pb.SecretVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, name, n, err := f.resolve(r.GetName())
	if err != nil {
		return nil, err
	}
	return f.version(name, s, n), nil
}

func (f *fakeProject) AccessSecretVersion(_ context.Context, r *pb.AccessSecretVersionRequest) (*pb.AccessSecretVersionResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, name, n, err := f.resolve(r.GetName())
	if err != nil {
		return nil, err
	}
	if s.disabled[n] {
		return nil, status.Error(codes.FailedPrecondition, "version disabled")
	}
	return &pb.AccessSecretVersionResponse{
		Name:    fmt.Sprintf("%s/versions/%d", name, n),
		Payload: &pb.SecretPayload{Data: s.versions[n-1]},
	}, nil
}

func (f *fakeProject) DeleteSecret(_ context.Context, r *pb.DeleteSecretRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.lookup(r.GetName()); err != nil {
		return err
	}
	delete(f.secrets, r.GetName())
	return nil
}

func (f *fakeProject) ListSecrets(_ context.Context, r *pb.ListSecretsRequest) ([]*pb.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	names := make([]string, 0, len(f.secrets))
	for n := range f.secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]*pb.Secret, 0, len(names))
	for _, n := range names {
		out = append(out, f.secrets[n].secret)
	}
	return out, nil
}

func (f *fakeProject) Close() error { f.closed = true; return nil }

func testStore(t *testing.T, proj *fakeProject, writes bool) *Store {
	t.Helper()
	return newStore(proj, Config{ProjectID: "p1", PollInterval: time.Second, AllowWrites: writes})
}

func TestPutGetRoundTrip(t *testing.T) {
	proj := newFakeProject()
	s := testStore(t, proj, true)
	ctx := context.Background()
	key := domain.MustKey("payments/prod/DB_URL")

	meta, err := s.Put(ctx, key, []byte("postgres://one"))
	if err != nil {
		t.Fatal(err)
	}
	if meta.Key.String() != key.String() || meta.Version.String() != "1" || meta.CreatedAt.IsZero() {
		t.Fatalf("meta = %+v, want key, version 1 and created set", meta)
	}

	stored, ok := proj.secrets["projects/p1/secrets/payments-1prod-1DB_URL"]
	if !ok {
		t.Fatal("secret not stored under the encoded id in the configured project")
	}
	if got := stored.secret.Annotations[keyAnnotation]; got != key.String() {
		t.Errorf("annotation %s = %q, want %q", keyAnnotation, got, key)
	}
	if stored.secret.GetReplication().GetAutomatic() == nil {
		t.Error("secret created without automatic replication")
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

	// A second Put adds version 2 to the same secret; creation time holds.
	meta2, err := s.Put(ctx, key, []byte("postgres://two"))
	if err != nil {
		t.Fatal(err)
	}
	if meta2.Version.String() != "2" {
		t.Errorf("second Put version = %s, want 2", meta2.Version)
	}
	if !meta2.CreatedAt.Equal(meta.CreatedAt) {
		t.Errorf("CreatedAt changed on overwrite: %s -> %s", meta.CreatedAt, meta2.CreatedAt)
	}
	if len(proj.secrets) != 1 {
		t.Errorf("%d secrets after two Puts of one key, want 1", len(proj.secrets))
	}
	got, _ = s.Get(ctx, key)
	if string(got.Value()) != "postgres://two" {
		t.Errorf("Get after overwrite = %q, want latest", got.Value())
	}
}

func TestGetNotFound(t *testing.T) {
	s := testStore(t, newFakeProject(), false)
	_, err := s.Get(context.Background(), domain.MustKey("payments/prod/MISSING"))
	if !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if status.Code(err) != codes.NotFound {
		t.Error("gRPC status dropped from the chain")
	}
}

func TestWriteGuards(t *testing.T) {
	ctx := context.Background()
	key := domain.MustKey("payments/prod/X")

	ro := testStore(t, newFakeProject(), false)
	if _, err := ro.Put(ctx, key, []byte("v")); !errors.Is(err, ports.ErrReadOnly) {
		t.Errorf("Put on read-only: err = %v, want ErrReadOnly", err)
	}
	if err := ro.Delete(ctx, key); !errors.Is(err, ports.ErrReadOnly) {
		t.Errorf("Delete on read-only: err = %v, want ErrReadOnly", err)
	}

	rw := testStore(t, newFakeProject(), true)
	if _, err := rw.Put(ctx, key, nil); !errors.Is(err, domain.ErrEmptyValue) {
		t.Errorf("Put empty: err = %v, want ErrEmptyValue", err)
	}
	if err := rw.Delete(ctx, key); !errors.Is(err, ports.ErrNotFound) {
		t.Errorf("Delete missing: err = %v, want ErrNotFound", err)
	}
}

func TestListFilters(t *testing.T) {
	proj := newFakeProject()
	s := testStore(t, proj, true)
	ctx := context.Background()

	for _, k := range []string{"payments/prod/A", "payments/dev/B", "payments/prod/C", "billing/D"} {
		if _, err := s.Put(ctx, domain.MustKey(k), []byte("v")); err != nil {
			t.Fatal(err)
		}
	}
	// A secret made by hand outside the encoding is ignored.
	if _, err := proj.CreateSecret(ctx, &pb.CreateSecretRequest{Parent: "projects/p1", SecretId: "my_db_password"}); err != nil {
		t.Fatal(err)
	}
	// An encoded secret with no versions yet is invisible, as Get would 404.
	if _, err := proj.CreateSecret(ctx, &pb.CreateSecretRequest{Parent: "projects/p1", SecretId: "payments-1prod-1EMPTY"}); err != nil {
		t.Fatal(err)
	}
	// One whose latest version is disabled is invisible too.
	if _, err := s.Put(ctx, domain.MustKey("payments/prod/OFF"), []byte("v")); err != nil {
		t.Fatal(err)
	}
	proj.secrets["projects/p1/secrets/payments-1prod-1OFF"].disabled[1] = true

	metas, err := s.List(ctx, domain.MustNamespace("payments"))
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(metas))
	for _, m := range metas {
		got = append(got, m.Key.String()+"@"+m.Version.String())
	}
	want := []string{"payments/dev/B@1", "payments/prod/A@1", "payments/prod/C@1"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("list = %v, want %v", got, want)
	}
}

func TestDeleteIsPermanent(t *testing.T) {
	s := testStore(t, newFakeProject(), true)
	ctx := context.Background()
	key := domain.MustKey("payments/prod/A")

	if _, err := s.Put(ctx, key, []byte("v")); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, key); !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("Get after delete: err = %v, want ErrNotFound", err)
	}
	// The id is reusable immediately and versions restart at 1.
	meta, err := s.Put(ctx, key, []byte("again"))
	if err != nil {
		t.Fatal(err)
	}
	if meta.Version.String() != "1" {
		t.Errorf("version after recreate = %s, want 1", meta.Version)
	}
}

func TestWatchEmitsSnapshotAndChanges(t *testing.T) {
	proj := newFakeProject()
	s := testStore(t, proj, true)
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
	next := func(want domain.Type, version string) {
		t.Helper()
		select {
		case ev := <-events:
			if ev.Type != want || (version != "" && ev.Meta.Version.String() != version) {
				t.Fatalf("event = %s %q@%s, want %s @%s", ev.Type, ev.Meta.Key, ev.Meta.Version, want, version)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for %s", want)
		}
	}
	next(domain.Added, "1")
	next(domain.InSync, "")

	if _, err := s.Put(ctx, key, []byte("v2")); err != nil {
		t.Fatal(err)
	}
	next(domain.Updated, "2")

	if err := s.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	next(domain.Deleted, "")
}

func TestClose(t *testing.T) {
	proj := newFakeProject()
	testStore(t, proj, false).Close()
	if !proj.closed {
		t.Error("Close did not reach the client")
	}
}

func TestConfigValidate(t *testing.T) {
	if err := (Config{ProjectID: "p", PollInterval: 30 * time.Second}).Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for i, c := range []Config{
		{PollInterval: 30 * time.Second},
		{ProjectID: "p"},
		{ProjectID: "p", PollInterval: 100 * time.Millisecond},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("config %d accepted: %+v", i, c)
		}
	}
}
