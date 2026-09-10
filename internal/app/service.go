package app

import (
	"context"
	"errors"

	"github.com/IbiliAze/vaultlet/internal/domain"
	"github.com/IbiliAze/vaultlet/internal/ports"
)

var (
	ErrPermissionDenied = errors.New("permission denied")
)

type Service struct {
	store  ports.SecretStore
	policy Policy
}

func NewService(store ports.SecretStore, policy Policy) *Service {
	return &Service{
		store:  store,
		policy: policy,
	}
}

func (s *Service) Get(ctx context.Context, key domain.Key) (domain.Secret, error) {
	principal, ok := PrincipalFromContext(ctx)
	if !ok || !s.policy.allows(principal, ActionGet, key.Namespace()) {
		audit(ctx, principal, ActionGet, key.String(), "deny", "denied")
		return domain.Secret{}, ErrPermissionDenied
	}

	secret, err := s.store.Get(ctx, key)

	outcome := "success"
	if err != nil {
		outcome = "error"
	}

	audit(ctx, principal, ActionGet, key.String(), "allow", outcome)
	return secret, err
}

func (s *Service) Put(ctx context.Context, key domain.Key, value []byte) (domain.SecretMeta, error) {
	principal, ok := PrincipalFromContext(ctx)
	if !ok || !s.policy.allows(principal, ActionPut, key.Namespace()) {
		audit(ctx, principal, ActionPut, key.String(), "deny", "denied")
		return domain.SecretMeta{}, ErrPermissionDenied
	}

	meta, err := s.store.Put(ctx, key, value)

	outcome := "success"
	if err != nil {
		outcome = "error"
	}

	audit(ctx, principal, ActionPut, key.String(), "allow", outcome)
	return meta, err
}

func (s *Service) List(ctx context.Context, ns domain.Namespace) ([]domain.SecretMeta, error) {
	principal, ok := PrincipalFromContext(ctx)
	if !ok || !s.policy.canList(principal, ns) {
		audit(ctx, principal, ActionList, ns.String(), "deny", "denied")
		return nil, ErrPermissionDenied
	}

	metas, err := s.store.List(ctx, ns)
	if err != nil {
		audit(ctx, principal, ActionList, ns.String(), "allow", "error")
		return nil, err
	}

	visible := make([]domain.SecretMeta, 0, len(metas))
	for _, meta := range metas {
		keyNS := meta.Key.Namespace()
		if ns.Contains(keyNS) &&
			s.policy.allows(principal, ActionList, keyNS) {
			visible = append(visible, meta)
		}
	}

	audit(ctx, principal, ActionList, ns.String(), "allow", "success")
	return visible, nil
}

func (s *Service) Delete(ctx context.Context, key domain.Key) error {
	principal, ok := PrincipalFromContext(ctx)
	if !ok || !s.policy.allows(principal, ActionDelete, key.Namespace()) {
		audit(ctx, principal, ActionDelete, key.String(), "deny", "denied")
		return ErrPermissionDenied
	}

	err := s.store.Delete(ctx, key)

	outcome := "success"
	if err != nil {
		outcome = "error"
	}

	audit(ctx, principal, ActionDelete, key.String(), "allow", outcome)
	return err
}

func (s *Service) Watch(ctx context.Context, ns domain.Namespace) (<-chan domain.SecretEvent, error) {
	principal, ok := PrincipalFromContext(ctx)
	if !ok || !s.policy.canWatch(principal, ns) {
		audit(ctx, principal, ActionWatch, ns.String(), "deny", "denied")
		return nil, ErrPermissionDenied
	}

	src, err := s.store.Watch(ctx, ns)
	if err != nil {
		audit(ctx, principal, ActionWatch, ns.String(), "allow", "error")
		return nil, err
	}

	audit(ctx, principal, ActionWatch, ns.String(), "allow", "success")
	return s.filterEvents(ctx, principal, ns, src), nil
}

// filterEvents applies the same per-key check List does to every event on
// src, so a subscriber to an ancestor namespace only sees keys it may watch.
// IN_SYNC carries no key and always passes. The returned channel closes when
// src closes or ctx ends.
func (s *Service) filterEvents(ctx context.Context, principal string, ns domain.Namespace, src <-chan domain.SecretEvent) <-chan domain.SecretEvent {
	out := make(chan domain.SecretEvent)

	go func() {
		defer close(out)
		for ev := range src {
			if ev.Type != domain.InSync && !s.visible(principal, ns, ev.Meta) {
				continue
			}
			select {
			case out <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()

	return out
}

// visible mirrors List's filter: the key must sit under the requested
// namespace and the principal must hold both list and watch there, matching
// what canWatch demanded at subscribe time.
func (s *Service) visible(principal string, ns domain.Namespace, meta domain.SecretMeta) bool {
	keyNS := meta.Key.Namespace()
	return ns.Contains(keyNS) &&
		s.policy.allows(principal, ActionList, keyNS) &&
		s.policy.allows(principal, ActionWatch, keyNS)
}

var _ ports.SecretStore = (*Service)(nil)
