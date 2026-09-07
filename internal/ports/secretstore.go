package ports

import (
	"context"
	"errors"

	"github.com/IbiliAze/vaultlet/internal/domain"
)

// ErrNotFound is returned by Get and Delete when no secret exists at the key.
// Every backend must wrap this so callers can test with errors.Is.
var ErrNotFound = errors.New("secret not found")
var ErrReadOnly = errors.New("store is read-only")

type SecretStore interface {
	Get(context.Context, domain.Key) (domain.Secret, error)
	Put(context.Context, domain.Key, []byte) (domain.SecretMeta, error)
	List(context.Context, domain.Namespace) ([]domain.SecretMeta, error)
	Delete(context.Context, domain.Key) error
	Watch(context.Context, domain.Namespace) (<-chan domain.SecretEvent, error)
}
