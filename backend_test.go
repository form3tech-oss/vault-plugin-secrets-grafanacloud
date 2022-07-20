package secretsengine

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const (
	envVarRunAccTests              = "VAULT_ACC"
	envVarGrafanaCloudOrganisation = "TEST_GRAFANA_CLOUD_ORGANISATION"
	envVarGrafanaCloudAPIKey       = "TEST_GRAFANA_CLOUD_API_KEY"
	envVarGrafanaCloudURL          = "TEST_GRAFANA_CLOUD_URL"
)

// getTestBackend will help you construct a test backend object.
// Update this function with your target backend.
func getTestBackend(tb testing.TB) (*grafanaCloudBackend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = logical.TestSystemView()

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}

	return b.(*grafanaCloudBackend), config.StorageView
}

// runAcceptanceTests will separate unit tests from
// acceptance tests, which will make active requests
// to your target API.
var runAcceptanceTests = os.Getenv(envVarRunAccTests) == "1"

// testEnv creates an object to store and track testing environment
// resources
type testEnv struct {
	// Password string
	Organisation string
	Key          string
	URL          string
	User         string

	Backend logical.Backend
	Context context.Context
	Storage logical.Storage

	// SecretToken tracks the API token, for checking rotations
	SecretToken string

	// Tokens tracks the generated tokens, to make sure we clean up
	Names []string
}

// AddConfig adds the configuration to the test backend.
// Make sure data includes all of the configuration
// attributes you need and the `config` path!
func (e *testEnv) AddConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"organisation": e.Organisation,
			"key":          e.Key,
			"url":          e.URL,
			"user":         e.User,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

// AddUserTokenRole adds a role for the Grafana Cloud
// API token.
func (e *testEnv) AddUserTokenRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-user-token",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"gc_role": "Viewer",
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

// ReadUserToken retrieves the user token
// based on a Vault role.
func (e *testEnv) ReadUserToken(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-user-token",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Secret.InternalData["name"])
	require.NotNil(t, resp.Secret)
	require.Equal(t, testUser, resp.Data["user"])

	if e.SecretToken != "" {
		require.NotEqual(t, e.SecretToken, resp.Data["token"])
	}

	e.SecretToken = resp.Data["token"].(string)

	if t, ok := resp.Secret.InternalData["name"]; ok {
		e.Names = append(e.Names, t.(string))
	}
}

// CleanupUserTokens removes the tokens
// when the test completes.
func (e *testEnv) CleanupUserTokens(t *testing.T) {
	if len(e.Names) == 0 {
		t.Fatalf("expected 2 tokens, got: %d", len(e.Names))
	}

	for _, token := range e.Names {
		b := e.Backend.(*grafanaCloudBackend)
		client, err := b.getClient(e.Context, e.Storage)
		if err != nil {
			t.Fatal("fatal getting client")
		}

		err = client.DeleteAPIKey(e.Context, e.Organisation, token)
		if err != nil {
			t.Fatalf("unexpected error deleting API key: %s", err)
		}
	}
}
