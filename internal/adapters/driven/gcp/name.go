package gcp

import (
	"errors"
	"fmt"
	"strings"

	"github.com/IbiliAze/vaultlet/internal/domain"
)

// Secret Manager IDs allow [A-Za-z0-9_-], at most 255 characters, and are
// case-sensitive, so only '/', '.' and the escape character itself need
// escaping. '-' is the escape and is always followed by one digit:
//
//	"-" -> "-0"    "/" -> "-1"    "." -> "-2"
//
// payments/prod/DB_URL becomes payments-1prod-1DB_URL. Put also records
// the canonical key in the vaultlet-key annotation.

const (
	maxIDLen      = 255
	keyAnnotation = "vaultlet-key"
)

var errIDTooLong = errors.New("key too long for Secret Manager")

func encodeID(key domain.Key) (string, error) {
	var b strings.Builder
	for _, r := range key.String() {
		switch r {
		case '-':
			b.WriteString("-0")
		case '/':
			b.WriteString("-1")
		case '.':
			b.WriteString("-2")
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > maxIDLen {
		return "", fmt.Errorf("%w: %s encodes to %d characters, max %d", errIDTooLong, key, b.Len(), maxIDLen)
	}
	return b.String(), nil
}

// decodeID inverts encodeID. IDs written outside vaultlet may not follow the
// scheme; those come back as an error and List skips them.
func decodeID(id string) (domain.Key, error) {
	var b strings.Builder
	for i := 0; i < len(id); i++ {
		c := id[i]
		if c != '-' {
			b.WriteByte(c)
			continue
		}
		i++
		if i >= len(id) {
			return domain.Key{}, fmt.Errorf("%w: %q ends in an escape", domain.ErrInvalidKey, id)
		}
		switch id[i] {
		case '0':
			b.WriteByte('-')
		case '1':
			b.WriteByte('/')
		case '2':
			b.WriteByte('.')
		default:
			return domain.Key{}, fmt.Errorf("%w: %q has bad escape %q", domain.ErrInvalidKey, id, id[i-1:i+1])
		}
	}
	return domain.ParseKey(b.String())
}
