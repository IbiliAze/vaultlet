package config

import (
	"errors"
	"io/fs"
	"strings"

	"github.com/IbiliAze/vaultlet/internal/adapters/driven/azure"
	"github.com/IbiliAze/vaultlet/internal/adapters/driven/bitwarden"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/dotenv"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
)

type TLSConfig struct {
	CertFile string `koanf:"cert_file"`
	KeyFile  string `koanf:"key_file"`
}

type UserConfig struct {
	Username     string            `koanf:"username"`
	PasswordHash string            `koanf:"password_hash"`
	Allow        []UserAllowConfig `koanf:"allow"`
}

type UserAllowConfig struct {
	Namespace string   `koanf:"namespace"`
	Actions   []string `koanf:"actions"`
}

type AuthConfig struct {
	Users []UserConfig `koanf:"users"`
}

type Config struct {
	Listen    string           `koanf:"listen"`
	Backend   string           `koanf:"backend"`
	Bitwarden bitwarden.Config `koanf:"bitwarden"`
	Azure     azure.Config     `koanf:"azure"`
	TLS       TLSConfig        `koanf:"tls"`
	Auth      AuthConfig       `koanf:"auth"`
}

func Load() (Config, error) {
	k := koanf.New(".")

	// 1. Base config
	if err := k.Load(file.Provider("vaultlet.yaml"), yaml.Parser()); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return Config{}, err
		}
	}

	// 2. .env overrides YAML
	if err := k.Load(file.Provider(".env"), dotenv.ParserEnv(
		"VAULTLET_",
		".",
		func(s string) string {
			s = strings.ToLower(strings.TrimPrefix(s, "VAULTLET_"))
			return strings.ReplaceAll(s, "__", ".")
		},
	)); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return Config{}, err
		}
	}

	// 3. Real environment variables override everything
	if err := k.Load(env.Provider("VAULTLET_", ".", func(s string) string {
		s = strings.ToLower(strings.TrimPrefix(s, "VAULTLET_"))
		return strings.ReplaceAll(s, "__", ".")
	}), nil); err != nil {
		return Config{}, err
	}

	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if c.Backend == "" {
		return errors.New("config: backend required")
	}
	if c.Listen == "" {
		return errors.New("config: listen required")
	}
	if c.TLS.CertFile == "" {
		return errors.New("config: tls.cert_file required")
	}
	if c.TLS.KeyFile == "" {
		return errors.New("config: tls.key_file required")
	}
	if len(c.Auth.Users) == 0 {
		return errors.New("config: auth.users required")
	}
	for _, user := range c.Auth.Users {
		if user.Username == "" {
			return errors.New("config: auth.users[].username required")
		}
		if user.PasswordHash == "" {
			return errors.New("config: auth.users[].password_hash required")
		}
		if len(user.Allow) == 0 {
			return errors.New("config: auth.users[].allow required")
		}

		for _, rule := range user.Allow {
			if rule.Namespace == "" {
				return errors.New("config: auth.users[].allow[].namespace required")
			}
		}
	}
	return nil
}
