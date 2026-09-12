package gcp

import (
	"errors"
	"strings"
	"testing"

	"github.com/IbiliAze/vaultlet/internal/domain"
)

func TestIDRoundTrip(t *testing.T) {
	tests := []struct{ key, id string }{
		{"payments/prod/DB_URL", "payments-1prod-1DB_URL"},
		{"ci-build/prod/x", "ci-0build-1prod-1x"},
		{"a/b.c-d_e", "a-1b-2c-0d_e"},
		{"a/1", "a-11"}, // digit after "-1" is data, not another escape
	}
	for _, tc := range tests {
		t.Run(tc.key, func(t *testing.T) {
			got, err := encodeID(domain.MustKey(tc.key))
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.id {
				t.Fatalf("encode = %q, want %q", got, tc.id)
			}
			for _, c := range got {
				ok := c == '-' || c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
				if !ok {
					t.Fatalf("encoded id %q contains %q, outside Secret Manager's alphabet", got, c)
				}
			}
			back, err := decodeID(got)
			if err != nil {
				t.Fatal(err)
			}
			if back.String() != tc.key {
				t.Fatalf("decode = %q, want %q", back, tc.key)
			}
		})
	}
}

func TestEncodeIDTooLong(t *testing.T) {
	// Eight 63-character segments plus a name is well past 255 once the
	// slashes are escaped.
	seg := strings.Repeat("a", 63)
	key := domain.MustKey(strings.Repeat(seg+"/", 4) + "NAME")
	if _, err := encodeID(key); !errors.Is(err, errIDTooLong) {
		t.Fatalf("err = %v, want errIDTooLong", err)
	}
}

func TestDecodeIDRejectsForeign(t *testing.T) {
	for _, id := range []string{"plain", "ends-", "bad-9", "trailing-1", "-1x", "my_db_password"} {
		if _, err := decodeID(id); err == nil {
			t.Errorf("decodeID(%q) succeeded, want error", id)
		}
	}
}
