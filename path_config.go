package secretsengine

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"net/url"
)

const (
	configStoragePath = "config"
)

// grafanaConfig includes the minimum configuration required to instantiate a new GrafanaCloud client.
type grafanaCloudConfig struct {
	Organisation string `json:"organisation"`
	Key          string `json:"key"`
	URL          string `json:"url"`
	User         string `json:"user"`
}

// pathConfig extends the Vault API with a `/config`
// endpoint for the backend. You can choose whether
// or not certain attributes should be displayed,
// required, and named. For example, password
// is marked as sensitive and will not be output
// when you read the configuration.
func pathConfig(b *grafanaCloudBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"key": {
				Type:        framework.TypeString,
				Description: "API key with Admin role to create user keys",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Admin Key",
					Sensitive: true,
				},
			},
			"organisation": {
				Type:        framework.TypeString,
				Description: "The Organisation slug for the Grafana Cloud API",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Organisation",
					Sensitive: false,
				},
			},
			"url": {
				Type:        framework.TypeString,
				Description: "The URL for the Grafana Cloud API",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "URL",
					Sensitive: false,
				},
			},
			"user": {
				Type:        framework.TypeString,
				Description: "The User that is needed to interact with prometheus, if set this is returned alongside every issued credential",
				Required:    false,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "User",
					Sensitive: true,
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
			},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}
}

// pathConfigExistenceCheck verifies if the configuration exists.
func (b *grafanaCloudBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

func getConfig(ctx context.Context, s logical.Storage) (*grafanaCloudConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(grafanaCloudConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}

	// return the config, we are done
	return config, nil
}

func (b *grafanaCloudBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"organisation": config.Organisation,
			"key":          config.Key,
			"url":          config.URL,
			"user":         config.User,
		},
	}, nil
}

func (b *grafanaCloudBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	createOperation := req.Operation == logical.CreateOperation

	if config == nil {
		if !createOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = new(grafanaCloudConfig)
	}

	if organisation, ok := data.GetOk("organisation"); ok {
		config.Organisation = organisation.(string)
	}

	if config.Organisation == "" && createOperation {
		return nil, fmt.Errorf("missing organisation in configuration")
	}

	if key, ok := data.GetOk("key"); ok {
		config.Key = key.(string)
	}

	if config.Key == "" && createOperation {
		return nil, fmt.Errorf("missing key in configuration")
	}

	if configuredUrl, ok := data.GetOk("url"); ok {
		config.URL = configuredUrl.(string)
		if u, err := url.ParseRequestURI(config.URL); err != nil || !u.IsAbs() {
			return nil, fmt.Errorf("invalid url in configuration")
		}
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing url in configuration")
	}

	if user, ok := data.GetOk("user"); ok {
		config.User = user.(string)
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.reset()

	return nil, nil
}

func (b *grafanaCloudBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configStoragePath)

	if err == nil {
		b.reset()
	}

	return nil, err
}

// pathConfigHelpSynopsis summarizes the help text for the configuration
const pathConfigHelpSynopsis = `Configure the Grafana Cloud backend.`

// pathConfigHelpDescription describes the help text for the configuration
const pathConfigHelpDescription = `
The Grafana Cloud secret backend requires credentials for managing
API keys that it issues.
`
