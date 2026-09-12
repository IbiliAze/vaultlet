// Package watch turns a backend's List into a stream of SecretEvents by
// polling. Backends without native change notification (Bitwarden, Azure
// Key Vault) call Poll from their Watch method so the snapshot, diff and
// cancellation rules live in exactly one place.
package watch

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/IbiliAze/vaultlet/internal/domain"
)

// ListFunc is the snapshot source a poller diffs. It is the adapter's own
// List, so every error it returns already carries the backend prefix.
type ListFunc func(context.Context, domain.Namespace) ([]domain.SecretMeta, error)

// Poll takes one snapshot of ns synchronously and returns a channel that
// replays it as Added events, sends InSync, then emits Added, Updated and
// Deleted as later snapshots differ. A poll that fails is logged and skipped;
// the stream stays open. The channel closes when ctx ends.
//
// The first List runs before Poll returns so a backend that is down at
// subscribe time surfaces as an error to the caller rather than as a stream
// that closes with nothing on it.
func Poll(ctx context.Context, ns domain.Namespace, interval time.Duration, list ListFunc) (<-chan domain.SecretEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	snapshot, err := list(ctx, ns)
	if err != nil {
		return nil, err
	}

	c := make(chan domain.SecretEvent)

	go func() {
		defer close(c)

		// emit delivers ev unless the subscriber is gone. Without the
		// select a goroutine parked on an unbuffered send would never
		// observe ctx and would leak once the gRPC handler returns.
		emit := func(ev domain.SecretEvent) bool {
			select {
			case c <- ev:
				return true
			case <-ctx.Done():
				return false
			}
		}

		seen := make(map[string]domain.SecretMeta, len(snapshot))
		for _, meta := range snapshot {
			seen[meta.Key.String()] = meta
			if !emit(domain.SecretEvent{Type: domain.Added, Meta: meta}) {
				return
			}
		}
		if !emit(domain.SecretEvent{Type: domain.InSync}) {
			return
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			metas, err := list(ctx, ns)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				slog.WarnContext(ctx, "watch poll failed", "namespace", ns.String(), "err", err)
				continue
			}

			present := make(map[string]bool, len(metas))
			for _, meta := range metas {
				k := meta.Key.String()
				present[k] = true

				prev, exists := seen[k]
				if exists && prev.Version == meta.Version {
					continue
				}
				seen[k] = meta

				typ := domain.Updated
				if !exists {
					typ = domain.Added
				}
				if !emit(domain.SecretEvent{Type: typ, Meta: meta}) {
					return
				}
			}

			// Sorted so a burst of deletions arrives in a stable order.
			gone := make([]string, 0)
			for k := range seen {
				if !present[k] {
					gone = append(gone, k)
				}
			}
			slices.SortFunc(gone, strings.Compare)
			for _, k := range gone {
				meta := seen[k]
				delete(seen, k)
				if !emit(domain.SecretEvent{Type: domain.Deleted, Meta: meta}) {
					return
				}
			}
		}
	}()

	return c, nil
}
