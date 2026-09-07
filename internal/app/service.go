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
	if !ok || !s.policy.canList(principal, ns) {
		audit(ctx, principal, ActionList, ns.String(), "deny", "denied")
		return nil, ErrPermissionDenied
	}

	return nil, nil
}

var _ ports.SecretStore = (*Service)(nil)
