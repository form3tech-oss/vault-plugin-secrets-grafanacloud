package secretsengine

import (
	"fmt"
	"os"
	"sync"
	"testing"

	stepwise "github.com/hashicorp/vault-testing-stepwise"
	dockerEnvironment "github.com/hashicorp/vault-testing-stepwise/environments/docker"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

// TestAccUserToken runs a series of acceptance tests to check the
// end-to-end workflow of the backend. It creates a Vault Docker container
// and loads a temporary plugin.
func TestAccUserToken(t *testing.T) {
	t.Parallel()
	if !runAcceptanceTests {
		t.SkipNow()
	}
	envOptions := &stepwise.MountOptions{
		RegistryName:    "grafana",
		PluginType:      stepwise.PluginTypeSecrets,
		PluginName:      "vault-plugin-secrets-grafanacloud",
		MountPathPrefix: "grafana",
	}

	roleName := "vault-stepwise-user-role"

	cred := new(string)
	stepwise.Run(t, stepwise.Case{
		Precheck:    func() { testAccPreCheck(t) },
		Environment: dockerEnvironment.NewEnvironment("grafana-cloud", envOptions),
		Steps: []stepwise.Step{
			testAccConfig(t),
			testAccUserRole(t, roleName),
			testAccUserRoleRead(t, roleName),
			testAccUserCredRead(t, roleName, cred),
		},
	})
}

var initSetup sync.Once

func testAccPreCheck(t *testing.T) {
	initSetup.Do(func() {
		// Ensure test variables are set
		if v := os.Getenv(envVarGrafanaCloudAPIKey); v == "" {
			t.Skip(fmt.Printf("%s not set", envVarGrafanaCloudAPIKey))
		}
		if v := os.Getenv(envVarGrafanaCloudURL); v == "" {
			t.Skip(fmt.Printf("%s not set", envVarGrafanaCloudURL))
		}
		if v := os.Getenv(envVarGrafanaCloudOrganisation); v == "" {
			t.Skip(fmt.Printf("%s not set", envVarGrafanaCloudOrganisation))
		}
	})
}

func testAccConfig(t *testing.T) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.UpdateOperation,
		Path:      "config",
		Data: map[string]interface{}{
			"organisation": os.Getenv(envVarGrafanaCloudOrganisation),
			"key":          os.Getenv(envVarGrafanaCloudAPIKey),
			"url":          os.Getenv(envVarGrafanaCloudURL),
		},
	}
}

func testAccUserRole(t *testing.T, roleName string) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.UpdateOperation,
		Path:      "roles/" + roleName,
		Data: map[string]interface{}{
			"gc_role": "Viewer",
			"ttl":     "1m",
			"max_ttl": "5m",
		},
		Assert: func(resp *api.Secret, err error) error {
			require.Nil(t, resp)
			require.Nil(t, err)
			return nil
		},
	}
}

func testAccUserRoleRead(t *testing.T, roleName string) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.ReadOperation,
		Path:      "roles/" + roleName,
		Assert: func(resp *api.Secret, err error) error {
			require.NotNil(t, resp)
			require.Equal(t, "Viewer", resp.Data["gc_role"])
			return nil
		},
	}
}

func testAccUserCredRead(t *testing.T, roleName string, apiKey *string) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.ReadOperation,
		Path:      "creds/" + roleName,
		Assert: func(resp *api.Secret, err error) error {
			require.NotNil(t, resp)
			require.NotEmpty(t, resp.Data["token"])
			*apiKey = resp.Data["token"].(string)
			return nil
		},
	}
}
