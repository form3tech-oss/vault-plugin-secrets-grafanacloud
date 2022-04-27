package secretsengine

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"

	"github.com/form3tech-oss/vault-plugin-secrets-grafanacloud/client"
	uuid "github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/logical"
)

type GrafanaCloudKey struct {
	Name  string
	Token string
	User  string
}

func (b *grafanaCloudBackend) grafanaCloudKey() *framework.Secret {
	return &framework.Secret{
		Type: grafanaCloudKeyType,
		Fields: map[string]*framework.FieldSchema{
			"user": {
				Type:        framework.TypeString,
				Description: "Grafana cloud api credentials username",
			},
			"token": {
				Type:        framework.TypeString,
				Description: "Grafana cloud api credentials Token",
			},
		},
		Revoke: b.keyRevoke,
		Renew:  b.keyRenew,
	}
}

func (b *grafanaCloudBackend) keyRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	org := config.Organisation
	tokenID := req.Secret.InternalData["name"].(string)
	err = c.DeleteAPIKey(ctx, org, tokenID)
	if err != nil {
		return nil, err
	}

	return &logical.Response{}, nil
}

func (b *grafanaCloudBackend) keyRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("secret is missing role internal data")
	}

	role := roleRaw.(string)
	roleEntry, err := b.getRole(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	resp := &logical.Response{Secret: req.Secret}

	if roleEntry.TTL > 0 {
		resp.Secret.TTL = roleEntry.TTL
	}
	if roleEntry.MaxTTL > 0 {
		resp.Secret.MaxTTL = roleEntry.MaxTTL
	}

	return resp, nil
}

func createKey(ctx context.Context, c *client.Client, organisation, roleName, user, grafanaCloudRole string) (*GrafanaCloudKey, error) {
	suffix := uuid.New().String()
	tokenName := fmt.Sprintf("%s_%s", roleName, suffix)

	key, err := c.CreateAPIKey(ctx, &client.CreateAPIKeyInput{
		Name:         tokenName,
		Role:         grafanaCloudRole,
		Organisation: organisation,
	})

	if err != nil {
		return nil, fmt.Errorf("error creating Grafana Cloud key: %w", err)
	}

	return &GrafanaCloudKey{
		Name:  key.Name,
		Token: key.Token,
		User:  user,
	}, nil
}
