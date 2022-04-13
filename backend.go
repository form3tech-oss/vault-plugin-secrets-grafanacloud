package secretsengine

import (
	"context"
	"strings"
	"sync"

	"github.com/form3tech-oss/vault-plugin-secrets-grafanacloud/client"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const grafanaCloudKeyType = "GrafanaCloudKey"

// CreateGrafanaAPIKeyInput grafana cloud data structure to create api credentials
type CreateGrafanaAPIKeyInput struct {
	Name          string `json:"name"`
	Role          string `json:"role"`
	SecondsToLive int    `json:"secondsToLive"`
	Stack         string `json:"-"`
}

// Factory returns a new backend as logical.Backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type grafanaCloudBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *client.Client
}

func backend() *grafanaCloudBackend {
	var b = grafanaCloudBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"config",
				"roles/*",
			},
		},
		Paths: framework.PathAppend(
			pathRole(&b),
			[]*framework.Path{
				pathConfig(&b),
				pathCredentials(&b),
			},
		),
		Secrets: []*framework.Secret{
			b.grafanaCloudKey(),
		},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}
	return &b
}

func (b *grafanaCloudBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

func (b *grafanaCloudBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

func (b *grafanaCloudBackend) getClient(ctx context.Context, s logical.Storage) (*client.Client, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = new(grafanaCloudConfig)
	}

	b.client, err = client.NewClient(config.URL, config.Key)
	if err != nil {
		return nil, err
	}

	return b.client, nil
}

const backendHelp = ``
