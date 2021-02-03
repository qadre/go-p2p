package p2p

import (
	"context"
	"github.com/stretchr/testify/assert"
	"strconv"
	"testing"
)

func TestStaticP2PIdentity(t *testing.T) {
	ctx := context.Background()
	opts := []Option{
		Port(30000),
		SecureIO(),
		PrivateKey("d2iA70NBphYNUobIVoqqnWNbLG9O5DckMYol6VTwT5yJbwai/hkx8DfiX1hb5NmQr9rdiRY64l+wdRm1/vTCSg=="),
		MasterKey(strconv.Itoa(1)),
	}

	host, err := NewHost(ctx, opts...)
	assert.NoError(t, err)

	host2, err := NewHost(ctx, opts...)
	assert.NoError(t, err)

	defer func() {
		assert.NoError(t, host.Close())
		assert.NoError(t, host2.Close())
	}()

	assert.Equal(t, host.HostIdentity(), host2.HostIdentity())
}
