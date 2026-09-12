package azure

import (
	"errors"
	"fmt"
	"net/url"
	"time"
)

var minPollInterval = time.Second

// Config is the Azure Key Vault backend's settings. Credentials are
// optional: when tenant_id, client_id and client_secret are all set a
// service-principal login is used, otherwise the SDK's default chain
// (AZURE_* environment variables, workload identity, managed identity,
// Azure CLI) applies.
type Config struct {
	VaultURL      string        `koanf:"vault_url"`
	TenantID      string        `koanf:"tenant_id"`
	ClientID      string        `koanf:"client_id"`
	ClientSecret  string        `koanf:"client_secret"`
	PollInterval  time.Duration `koanf:"poll_interval"`
	AllowWrites   bool          `koanf:"allow_writes"`
	PurgeOnDelete bool          `koanf:"purge_on_delete"`
}

func (c Config) Validate() error {
	if c.VaultURL == "" {
		return errors.New("azure: vault_url required")
	}
	u, err := url.Parse(c.VaultURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("azure: vault_url must be an https URL such as https://<name>.vault.azure.net")
	}

	// Either all three or none: a partial service-principal config would
	// silently fall through to the default chain and be very confusing.
	set := 0
	for _, v := range []string{c.TenantID, c.ClientID, c.ClientSecret} {
		if v != "" {
			set++
		}
	}
	if set != 0 && set != 3 {
		return errors.New("azure: tenant_id, client_id and client_secret must be set together")
	}

	if c.PollInterval == 0 {
		return errors.New("azure: poll_interval required")
	}
	if c.PollInterval < minPollInterval {
		return fmt.Errorf("azure: poll_interval must be at least %s", minPollInterval)
	}
	return nil
}

// explicitCredentials reports whether a service principal is configured.
func (c Config) explicitCredentials() bool {
	return c.TenantID != "" && c.ClientID != "" && c.ClientSecret != ""
}
