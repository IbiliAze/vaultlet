package aws

import "time"

type Config struct {
	Region       string        `koanf:"region"`
	Profile      string        `koanf:"profile"`
	Endpoint     string        `koanf:"endpoint"`
	PollInterval time.Duration `koanf:"poll_interval"`
	AllowWrites  bool          `koanf:"allow_writes"`
}
