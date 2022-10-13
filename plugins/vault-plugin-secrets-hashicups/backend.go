package secretsengine

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Factory returns a new backend as logical.Backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := createMyBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// myBacked defines an object that
// extends the Vault backend and stores the
// target API's client.
type myBackend struct {
	// implements logical.Backend
	*framework.Backend
	// locking mechanisms for writing or changing secrets engine data
	lock   sync.RWMutex
	// stores the client for the target API, HashiCups
	client *hashiCupsClient
}

// backend defines the target API backend
// for Vault. It must include each path
// and the secrets it will store.
func createMyBackend() *myBackend {
	b := myBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},
		Paths:       framework.PathAppend(),
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}
	return &b
}

// invalidate clears an existing client configuration in
// the backend
func (b *myBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		// reset clears any client configuration for a new
		// backend to be configured
		b.lock.Lock()
		defer b.lock.Unlock()
		b.client = nil
	}
}

// getClient locks the backend as it configures and creates a
// a new client for the target API
func (b *myBackend) getClient(ctx context.Context, s logical.Storage) (*hashiCupsClient, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	return nil, fmt.Errorf("need to return client")
}

// backendHelp should contain help information for the backend
const backendHelp = `
The myBackend secrets backend dynamically generates user tokens.
After mounting this backend, credentials to manage HashiCups user tokens
must be configured with the "config/" endpoints.
`
