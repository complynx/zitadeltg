package app

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrelinkPrivateHTTPRequiresExplicitOptIn(t *testing.T) {
	t.Parallel()
	f := newPrelinkFlow(t)
	p := f.config.Bots[0].Prelink
	p.Endpoint = "http://zinusya:9090" + prelinkPath
	require.Error(t, validatePrelink(p, f.config, "unrelated-bot-secret"))
	p.AllowHTTP = true
	require.NoError(t, validatePrelink(p, f.config, "unrelated-bot-secret"))
	for _, bad := range []string{
		"ftp://zinusya:9090" + prelinkPath,
		"http://zinusya:9090/another-path",
		"http://user:password@zinusya:9090" + prelinkPath,
		"http://zinusya:9090" + prelinkPath + "?redirect=1",
	} {
		p.Endpoint = bad
		require.Error(t, validatePrelink(p, f.config, "unrelated-bot-secret"))
	}
}
