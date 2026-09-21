package aws

import (
	"context"

	"github.com/IbiliAze/vaultlet/internal/domain"
	"github.com/IbiliAze/vaultlet/internal/ports"
	secretmanager "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type api interface {
	GetSecretValue()
	CreateSecret()
	PutSecretValue()
	DescribeSecret()
	ListSecrets()
	DeleteSecret()
}

type sdkClient struct{ c *secretmanager.Client }

type Store struct {
}

func (s *Store) Get(ctx context.Context, key domain.Key) (domain.Secret, error)

func (s *Store) Put(ctx context.Context, key domain.Key, value []byte) (domain.SecretMeta, error)

func (s *Store) List(ctx context.Context, ns domain.Namespace) ([]domain.SecretMeta, error)

func (s *Store) Delete(ctx context.Context, key domain.Key) error

func (s *Store) Watch(ctx context.Context, ns domain.Namespace) (<-chan domain.SecretEvent, error)

var _ ports.SecretStore = (*Store)(nil)
