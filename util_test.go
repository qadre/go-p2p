package p2p

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
)

func TestEnsureIPv4(t *testing.T) {
	lh := "localhost"
	addrs, err := net.DefaultResolver.LookupIP(context.Background(), "ip4", lh)
	assert.NoError(t, err)

	ip, err := EnsureIPv4(lh)
	require.NoError(t, err)
	contains(addrs, ip, t)

	ip, err = EnsureIPv4("127.0.0.1")
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", ip)

	_, err = EnsureIPv4("unknown")
	require.Error(t, err)
}

func contains(addresses []net.IP, addr string, t *testing.T) {
	for _, localAddress := range addresses {
		if localAddress.String() == addr {
			return
		}
	}

	t.Fail()
}
