package bitwarden

import (
	"errors"
	"fmt"
	"time"
)

type Config struct {
	APIURL       string        `koanf:"api_url"`
	OrgID        string        `koanf:"org_id"`
	IdentityURL  string        `koanf:"identity_url"`
	ProjectID    string        `koanf:"project_id"`
	AccessToken  string        `koanf:"access_token"`
	PollInterval time.Duration `koanf:"poll_interval"`
	AllowWrites  bool          `koanf:"allow_writes"`
}

func (c Config) Validate() error {
	if c.AccessToken == "" {
		return errors.New("bitwarden: access token required")
	}
	if c.ProjectID == "" {
		return errors.New("bitwarden: project_id required")
	}
	if c.OrgID == "" {
		return errors.New("bitwarden: org_id required")
	}
	if c.PollInterval == 0 {
		return errors.New("bitwarden: poll_interval required")
	}
	if c.PollInterval < time.Second {
		return fmt.Errorf("bitwarden: poll_interval must be at least %s", minPollInterval)
	}
	return nil
}
