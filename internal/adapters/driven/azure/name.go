package azure

import (
	"errors"
	"fmt"
	"strings"

	"github.com/IbiliAze/vaultlet/internal/domain"
)

// Key Vault secret names allow only [0-9a-zA-Z-], are at most 127 characters,
// and compare case-insensitively. A vaultlet key such as payments/prod/DB_URL
// therefore needs an injective encoding. '-' is the escape character, so
// every '-' in an encoded name is followed by exactly one code character:
//
//	"-" -> "-0"    "/" -> "-1"    "_" -> "-2"    "." -> "-3"
//	"A".."Z" -> "-a".."-z"
//
// payments/prod/DB_URL becomes payments-1prod-1-d-b-2-u-r-l. Ugly in the
// portal, which is why Put also stores the canonical key in the vaultlet-key
// tag, but it round-trips exactly and never collides.

const (
	maxNameLen = 127
	keyTag     = "vaultlet-key"
)

var errNameTooLong = errors.New("key too long for Key Vault")

func encodeName(key domain.Key) (string, error) {
	var b strings.Builder
	for _, r := range key.String() {
		switch {
		case r == '-':
			b.WriteString("-0")
		case r == '/':
			b.WriteString("-1")
		case r == '_':
			b.WriteString("-2")
		case r == '.':
			b.WriteString("-3")
		case r >= 'A' && r <= 'Z':
			b.WriteByte('-')
			b.WriteRune(r - 'A' + 'a')
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > maxNameLen {
		return "", fmt.Errorf("%w: %s encodes to %d characters, max %d", errNameTooLong, key, b.Len(), maxNameLen)
	}
	return b.String(), nil
}

// decodeName inverts encodeName. Names written outside vaultlet may not
// follow the scheme; those come back as an error and List skips them.
func decodeName(name string) (domain.Key, error) {
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c != '-' {
			b.WriteByte(c)
			continue
		}
		i++
		if i >= len(name) {
			return domain.Key{}, fmt.Errorf("%w: %q ends in an escape", domain.ErrInvalidKey, name)
		}
		switch e := name[i]; {
		case e == '0':
			b.WriteByte('-')
		case e == '1':
			b.WriteByte('/')
		case e == '2':
			b.WriteByte('_')
		case e == '3':
			b.WriteByte('.')
		case e >= 'a' && e <= 'z':
			b.WriteByte(e - 'a' + 'A')
		default:
			return domain.Key{}, fmt.Errorf("%w: %q has bad escape %q", domain.ErrInvalidKey, name, name[i-1:i+1])
		}
	}
	return domain.ParseKey(b.String())
}
