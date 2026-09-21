package aws

import (
	"errors"
	"fmt"
	"time"
)

var minPollInterval = time.Second

type Config struct {
	Region       string        `koanf:"region"`
	Profile      string        `koanf:"profile"`
	Endpoint     string        `koanf:"endpoint"`
	PollInterval time.Duration `koanf:"poll_interval"`
	AllowWrites  bool          `koanf:"allow_writes"`
}

func (c Config) Validate() error {
	if c.Region == "" {
		return errors.New("aws: region required")
	}

	if c.PollInterval == 0 {
		return errors.New("azure: poll_interval required")
	}
	if c.PollInterval < minPollInterval {
		return fmt.Errorf("azure: poll_interval must be at least %s", minPollInterval)
	}
	return nil
}
