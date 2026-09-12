package watch

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/IbiliAze/vaultlet/internal/domain"
)

// fakeList is a snapshot source the test mutates between polls.
type fakeList struct {
	mu    sync.Mutex
	metas []domain.SecretMeta
	err   error
	calls int
}

func (f *fakeList) list(_ context.Context, _ domain.Namespace) ([]domain.SecretMeta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return append([]domain.SecretMeta(nil), f.metas...), nil
}

func (f *fakeList) set(metas []domain.SecretMeta, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.metas = metas
	f.err = err
}

func meta(t *testing.T, key, version string) domain.SecretMeta {
	t.Helper()
	v, err := domain.NewVersion(version)
	if err != nil {
		t.Fatal(err)
	}
	return domain.SecretMeta{Key: domain.MustKey(key), Version: v}
}

// recv fails the test if no event arrives promptly. It returns ok=false
// when the channel closed instead.
func recv(t *testing.T, c <-chan domain.SecretEvent) (domain.SecretEvent, bool) {
	t.Helper()
	select {
	case ev, ok := <-c:
		return ev, ok
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for an event")
		return domain.SecretEvent{}, false
	}
}

func expect(t *testing.T, c <-chan domain.SecretEvent, typ domain.Type, key string) {
	t.Helper()
	ev, ok := recv(t, c)
	if !ok {
		t.Fatalf("channel closed, want %s %s", typ, key)
	}
	if ev.Type != typ || ev.Meta.Key.String() != key {
		t.Fatalf("got %s %q, want %s %q", ev.Type, ev.Meta.Key, typ, key)
	}
}

func TestPollSnapshotThenDiffs(t *testing.T) {
	ns := domain.MustNamespace("payments")
	src := &fakeList{metas: []domain.SecretMeta{
		meta(t, "payments/prod/A", "1"),
		meta(t, "payments/prod/B", "1"),
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c, err := Poll(ctx, ns, 5*time.Millisecond, src.list)
	if err != nil {
		t.Fatal(err)
	}

	expect(t, c, domain.Added, "payments/prod/A")
	expect(t, c, domain.Added, "payments/prod/B")
	expect(t, c, domain.InSync, "")

	// One key changes version, one is new, one disappears.
	src.set([]domain.SecretMeta{
		meta(t, "payments/prod/A", "2"),
		meta(t, "payments/prod/C", "1"),
	}, nil)

	expect(t, c, domain.Updated, "payments/prod/A")
	expect(t, c, domain.Added, "payments/prod/C")
	expect(t, c, domain.Deleted, "payments/prod/B")

	// An unchanged snapshot is silent: nothing may arrive before cancel.
	select {
	case ev := <-c:
		t.Fatalf("unexpected event %s %q on an unchanged snapshot", ev.Type, ev.Meta.Key)
	case <-time.After(30 * time.Millisecond):
	}

	cancel()
	if _, ok := recv(t, c); ok {
		t.Fatal("channel still open after cancel")
	}
}

func TestPollFailedPollIsSkipped(t *testing.T) {
	ns := domain.MustNamespace("payments")
	src := &fakeList{metas: []domain.SecretMeta{meta(t, "payments/prod/A", "1")}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c, err := Poll(ctx, ns, 5*time.Millisecond, src.list)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, c, domain.Added, "payments/prod/A")
	expect(t, c, domain.InSync, "")

	src.set(nil, errors.New("backend down"))

	// Several failed polls: nothing emitted, channel stays open. In
	// particular the known key must not be reported Deleted.
	select {
	case ev, ok := <-c:
		if !ok {
			t.Fatal("channel closed on a failed poll")
		}
		t.Fatalf("unexpected event %s %q during failed polls", ev.Type, ev.Meta.Key)
	case <-time.After(40 * time.Millisecond):
	}

	// Recovery resumes diffing from the last good snapshot.
	src.set([]domain.SecretMeta{meta(t, "payments/prod/A", "2")}, nil)
	expect(t, c, domain.Updated, "payments/prod/A")
}

func TestPollInitialSnapshotError(t *testing.T) {
	want := errors.New("backend down")
	src := &fakeList{err: want}

	c, err := Poll(context.Background(), domain.MustNamespace("payments"), time.Second, src.list)
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	if c != nil {
		t.Fatal("got a channel alongside an error")
	}
}

func TestPollCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	src := &fakeList{}
	c, err := Poll(ctx, domain.MustNamespace("payments"), time.Second, src.list)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if c != nil || src.calls != 0 {
		t.Fatalf("channel = %v, list calls = %d; want nil and 0", c, src.calls)
	}
}

func TestPollCancelWhileBlockedOnSend(t *testing.T) {
	src := &fakeList{metas: []domain.SecretMeta{meta(t, "payments/prod/A", "1")}}

	ctx, cancel := context.WithCancel(context.Background())
	c, err := Poll(ctx, domain.MustNamespace("payments"), time.Second, src.list)
	if err != nil {
		t.Fatal(err)
	}

	// Nobody reads the first Added event; cancelling must still close.
	cancel()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-c:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("channel did not close after cancel while sender was blocked")
		}
	}
}
