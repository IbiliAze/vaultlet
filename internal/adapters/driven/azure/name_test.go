package azure

import (
	"errors"
	"strings"
	"testing"

	"github.com/IbiliAze/vaultlet/internal/domain"
)

func TestNameRoundTrip(t *testing.T) {
	tests := []struct {
		key  string
		name string
	}{
		{"payments/prod/DB_URL", "payments-1prod-1-d-b-2-u-r-l"},
		{"ci-build/prod/x", "ci-0build-1prod-1x"},
		{"a/b.c-d_e", "a-1b-3c-0d-2e"},
		{"a/lower", "a-1lower"},
		{"a/1", "a-11"}, // digit after "-1" is data, not another escape
	}
	for _, tc := range tests {
		t.Run(tc.key, func(t *testing.T) {
			got, err := encodeName(domain.MustKey(tc.key))
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.name {
				t.Fatalf("encode = %q, want %q", got, tc.name)
			}
			for _, c := range got {
				if !(c == '-' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
					t.Fatalf("encoded name %q contains %q, outside Key Vault's alphabet", got, c)
				}
			}
			back, err := decodeName(got)
			if err != nil {
				t.Fatal(err)
			}
			if back.String() != tc.key {
				t.Fatalf("decode = %q, want %q", back, tc.key)
			}
		})
	}
}

func TestNameCaseDoesNotCollide(t *testing.T) {
	upper, _ := encodeName(domain.MustKey("a/DB"))
	lower, _ := encodeName(domain.MustKey("a/db"))
	if strings.EqualFold(upper, lower) {
		t.Fatalf("%q and %q collide under Key Vault's case-insensitive names", upper, lower)
	}
}

func TestEncodeNameTooLong(t *testing.T) {
	// 70 uppercase letters double to 140 encoded characters, past 127,
	// while the raw name stays inside the domain's 128 limit.
	key := domain.MustKey("ns/" + strings.Repeat("A", 70))
	if _, err := encodeName(key); !errors.Is(err, errNameTooLong) {
		t.Fatalf("err = %v, want errNameTooLong", err)
	}
}

func TestDecodeNameRejectsForeign(t *testing.T) {
	for _, name := range []string{"plain", "ends-", "bad-9", "trailing-1", "-1x"} {
		if _, err := decodeName(name); err == nil {
			t.Errorf("decodeName(%q) succeeded, want error", name)
		}
	}
}
