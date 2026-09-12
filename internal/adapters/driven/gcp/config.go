package gcp

import (
	"errors"
	"fmt"
	"time"
)

var minPollInterval = time.Second

// Config is the Google Cloud Secret Manager backend's settings. Credentials
// come from Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS,
// workload identity, the attached service account, gcloud auth) unless
// credentials_file points at a service-account key.
type Config struct {
	ProjectID       string        `koanf:"project_id"`
	CredentialsFile string        `koanf:"credentials_file"`
	PollInterval    time.Duration `koanf:"poll_interval"`
	AllowWrites     bool          `koanf:"allow_writes"`
}

func (c Config) Validate() error {
	if c.ProjectID == "" {
		return errors.New("gcp: project_id required")
	}
	if c.PollInterval == 0 {
		return errors.New("gcp: poll_interval required")
	}
	if c.PollInterval < minPollInterval {
		return fmt.Errorf("gcp: poll_interval must be at least %s", minPollInterval)
	}
	return nil
}
