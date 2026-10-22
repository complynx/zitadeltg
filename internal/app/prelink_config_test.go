package app

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func prelinkConfigYAML() string {
	return `issuer: https://idp.test/tg
email_domain: example.com
synthetic_email_verified: false
zitadel:
  jwt_endpoint: https://zitadel.test/idps/jwt
jwt:
  audience: iam-relay
bots:
  - token: 123456789:telegram-secret
    prelink:
      endpoint: https://zinusya.test/internal/identity/telegram-prelink
      audience: zinusya-prelink
      organization_id: fixture-org
      provider_id: fixture-idp
      service_bearer: ${PRELINK_TEST_KEY}
  - token: 987654321:other-secret
`
}

func TestPrelinkConfigIsPerBotAndExpandsSecret(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	t.Setenv("PRELINK_TEST_KEY", key)
	cfg, err := ParseConfig([]byte(prelinkConfigYAML()))
	require.NoError(t, err)
	require.Equal(t, key, cfg.Bots[0].Prelink.ServiceBearer)
	require.Equal(t, "fixture-org", cfg.Bots[0].Prelink.OrganizationID)
	require.Equal(t, PrelinkConfig{}, cfg.Bots[1].Prelink)
}

func TestPrelinkConfigRejectsIncompleteOrUnsafeTrust(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	t.Setenv("PRELINK_TEST_KEY", key)
	for _, tc := range []struct{ name, old, new string }{
		{"plaintext", "https://zinusya.test/internal/identity/telegram-prelink", "http://zinusya.test/internal/identity/telegram-prelink"},
		{"wrong path", "/internal/identity/telegram-prelink", "/internal/admin/tools"},
		{"userinfo", "https://zinusya.test", "https://secret-do-not-print@zinusya.test"},
		{"query", "https://zinusya.test/internal/identity/telegram-prelink", "https://zinusya.test/internal/identity/telegram-prelink?secret-do-not-print"},
		{"partial", "      organization_id: fixture-org\n", ""},
		{"shared audience", "audience: zinusya-prelink", "audience: iam-relay"},
		{"short key", "${PRELINK_TEST_KEY}", "secret-do-not-print"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(strings.Replace(prelinkConfigYAML(), tc.old, tc.new, 1)))
			require.Error(t, err)
			require.NotContains(t, err.Error(), key)
			require.NotContains(t, err.Error(), "secret-do-not-print")
		})
	}
}
