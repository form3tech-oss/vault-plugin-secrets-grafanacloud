package secretsengine

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathCredentials extends the Vault API with a `/creds`
// endpoint for a role. You can choose whether
// or not certain attributes should be displayed,
// required, and named.
func pathCredentials(b *grafanaCloudBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathCredentialsRead},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathCredentialsRead},
		},
		HelpSynopsis:    pathCredentialsHelpSyn,
		HelpDescription: pathCredentialsHelpDesc,
	}
}

const pathCredentialsHelpSyn = `
Generate a Grafana Cloud API key from a specific Vault role.
`

const pathCredentialsHelpDesc = `
This path generates a Grafana Cloud API key based on a particular role.
`

func (b *grafanaCloudBackend) createKey(ctx context.Context, s logical.Storage, roleName string, roleEntry *grafanaCloudRoleEntry) (*GrafanaCloudKey, error) {
	client, err := b.getClient(ctx, s)
	if err != nil {
		return nil, err
	}

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, fmt.Errorf("error reading secrets engine configuration: %w", err)
	}

	var token *GrafanaCloudKey
	token, err = createKey(ctx, client, config.Organisation, roleName, config.User, roleEntry.GrafanaCloudRole)

	if err != nil {
		return nil, fmt.Errorf("error creating Grafana Cloud token: %w", err)
	}

	if token == nil {
		return nil, errors.New("error creating Grafana Cloud token")
	}

	return token, nil
}

func (b *grafanaCloudBackend) createUserCreds(ctx context.Context, req *logical.Request, roleName string, role *grafanaCloudRoleEntry) (*logical.Response, error) {
	key, err := b.createKey(ctx, req.Storage, roleName, role)
	if err != nil {
		return nil, err
	}

	responseData := map[string]interface{}{
		"token": key.Token,
	}

	if key.User != "" {
		responseData["user"] = key.User
	}

	resp := b.Secret(grafanaCloudKeyType).Response(
		responseData,
		map[string]interface{}{"name": key.Name})

	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}

	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	return resp, nil
}

func (b *grafanaCloudBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	roleEntry, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	return b.createUserCreds(ctx, req, roleName, roleEntry)
}
