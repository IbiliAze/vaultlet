package aws

import "github.com/IbiliAze/vaultlet/internal/ports"

type Store struct {
}

var _ ports.SecretStore = (*Store)(nil)
