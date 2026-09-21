package aws

import (
	"context"

	"github.com/IbiliAze/vaultlet/internal/domain"
	"github.com/IbiliAze/vaultlet/internal/ports"
	secretmanager "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// api is the slice of the Secrets Manager client the store uses, so tests can
// swap in a fake. The SDK client holds no connections of its own, so there is
// no Close.
type api interface {
	GetSecretValue(ctx context.Context, in *secretmanager.GetSecretValueInput) (*secretmanager.GetSecretValueOutput, error)
	CreateSecret(ctx context.Context, in *secretmanager.CreateSecretInput) (*secretmanager.CreateSecretOutput, error)
	PutSecretValue(ctx context.Context, in *secretmanager.PutSecretValueInput) (*secretmanager.PutSecretValueOutput, error)
	DescribeSecret(ctx context.Context, in *secretmanager.DescribeSecretInput) (*secretmanager.DescribeSecretOutput, error)
	ListSecrets(ctx context.Context, in *secretmanager.ListSecretsInput) (*secretmanager.ListSecretsOutput, error)
	DeleteSecret(ctx context.Context, in *secretmanager.DeleteSecretInput) (*secretmanager.DeleteSecretOutput, error)
}

type sdkClient struct{ c *secretmanager.Client }

func (s sdkClient) GetSecretValue(ctx context.Context, in *secretmanager.GetSecretValueInput) (*secretmanager.GetSecretValueOutput, error) {
	return s.c.GetSecretValue(ctx, in)
}
func (s sdkClient) CreateSecret(ctx context.Context, in *secretmanager.CreateSecretInput) (*secretmanager.CreateSecretOutput, error) {
	return s.c.CreateSecret(ctx, in)
}
func (s sdkClient) PutSecretValue(ctx context.Context, in *secretmanager.PutSecretValueInput) (*secretmanager.PutSecretValueOutput, error) {
	return s.c.PutSecretValue(ctx, in)
}
func (s sdkClient) DescribeSecret(ctx context.Context, in *secretmanager.DescribeSecretInput) (*secretmanager.DescribeSecretOutput, error) {
	return s.c.DescribeSecret(ctx, in)
}
func (s sdkClient) ListSecrets(ctx context.Context, in *secretmanager.ListSecretsInput) (*secretmanager.ListSecretsOutput, error) {
	return s.c.ListSecrets(ctx, in)
}
func (s sdkClient) DeleteSecret(ctx context.Context, in *secretmanager.DeleteSecretInput) (*secretmanager.DeleteSecretOutput, error) {
	return s.c.DeleteSecret(ctx, in)
}

type Store struct {
	client api
}

func New(ctx context.Context, cfg Config) (*Store, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	client := secretmanager.New(secretmanager.Options{})
	return newStore(sdkClient{client}, cfg), nil
}

func newStore(client api, cfg Config) *Store {
	return &Store{
		client: client,
	}
}

func (s *Store) Get(ctx context.Context, key domain.Key) (domain.Secret, error)

func (s *Store) Put(ctx context.Context, key domain.Key, value []byte) (domain.SecretMeta, error)

func (s *Store) List(ctx context.Context, ns domain.Namespace) ([]domain.SecretMeta, error)

func (s *Store) Delete(ctx context.Context, key domain.Key) error

func (s *Store) Watch(ctx context.Context, ns domain.Namespace) (<-chan domain.SecretEvent, error)

var _ ports.SecretStore = (*Store)(nil)
