package secretsengine

import (
	"context"
	"strconv"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const (
	vaultRole  = "vaultRole"
	gcRole     = "Viewer"
	testTTL    = int64(120)
	testMaxTTL = int64(3600)
)

func TestUserRole(t *testing.T) {
	b, s := getTestBackend(t)

	t.Run("List All Roles", func(t *testing.T) {
		for i := 1; i <= 10; i++ {
			_, err := testTokenRoleCreate(t, b, s,
				vaultRole+strconv.Itoa(i),
				map[string]interface{}{
					"gc_role": gcRole,
					"ttl":     testTTL,
					"max_ttl": testMaxTTL,
				})
			require.NoError(t, err)
		}

		resp, err := testTokenRoleList(t, b, s)
		require.NoError(t, err)
		require.Len(t, resp.Data["keys"].([]string), 10)
	})

	t.Run("Create User Role - pass", func(t *testing.T) {
		resp, err := testTokenRoleCreate(t, b, s, vaultRole, map[string]interface{}{
			"gc_role": gcRole,
			"ttl":     testTTL,
			"max_ttl": testMaxTTL,
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})

	t.Run("Create User Role - fail on invalid", func(t *testing.T) {
		roleValues := map[string]interface{}{
			"Invalid role": "non-valid-grafana-cloud-vaultRole",
			"Blank role":   "",
			"Not a string": 100,
		}
		for d, r := range roleValues {
			t.Run(d, func(t *testing.T) {
				resp, err := testTokenRoleCreate(t, b, s, vaultRole, map[string]interface{}{
					"gc_role": r,
					"ttl":     testTTL,
					"max_ttl": testMaxTTL,
				})

				require.Nil(t, err)
				require.NotNil(t, resp)
				require.NotNil(t, resp.Error())
			})
		}
	})

	t.Run("Create User Role - fail on invalid TTL", func(t *testing.T) {
		ttlValues := map[string]interface{}{
			"Not a number":         "a",
			"Negative number":      -1,
			"Greater than max ttl": testMaxTTL + 10,
		}
		for d, v := range ttlValues {
			t.Run(d, func(t *testing.T) {
				resp, err := testTokenRoleCreate(t, b, s, vaultRole, map[string]interface{}{
					"gc_role": gcRole,
					"ttl":     v,
					"max_ttl": testMaxTTL,
				})

				require.Nil(t, err)
				require.NotNil(t, resp)
				require.NotNil(t, resp.Error())
			})
		}
	})

	t.Run("Create User Role - fail on invalid Max TTL", func(t *testing.T) {
		ttlValues := map[string]interface{}{
			"Not a number":    "a",
			"Negative number": -1,
			"Less than ttl":   testTTL - 10,
		}
		for d, v := range ttlValues {
			t.Run(d, func(t *testing.T) {
				resp, err := testTokenRoleCreate(t, b, s, vaultRole, map[string]interface{}{
					"gc_role": gcRole,
					"ttl":     testTTL,
					"max_ttl": v,
				})

				require.Nil(t, err)
				require.NotNil(t, resp)
				require.NotNil(t, resp.Error())
			})
		}
	})

	t.Run("Read User Role - existing", func(t *testing.T) {
		resp, err := testTokenRoleRead(t, b, s, vaultRole)

		require.Nil(t, err)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error())
		require.Equal(t, resp.Data["gc_role"], gcRole)
	})

	t.Run("Read User Role - non existent", func(t *testing.T) {
		resp, err := testTokenRoleRead(t, b, s, "non-existent-role")

		require.Nil(t, err)
		require.Nil(t, resp)
	})

	t.Run("Update User Role", func(t *testing.T) {
		resp, err := testTokenRoleUpdate(t, b, s, vaultRole, map[string]interface{}{
			"ttl":     "1m",
			"max_ttl": "5h",
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})

	t.Run("Re-read User Role - existing", func(t *testing.T) {
		resp, err := testTokenRoleRead(t, b, s, vaultRole)

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.NotNil(t, resp)
		require.Equal(t, resp.Data["gc_role"], gcRole)
	})

	t.Run("Delete User Role", func(t *testing.T) {
		_, err := testTokenRoleDelete(t, b, s)

		require.NoError(t, err)
	})
}

// Utility function to create a role while, returning any response (including errors)
func testTokenRoleCreate(t *testing.T, b *grafanaCloudBackend, s logical.Storage, roleName string, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/" + roleName,
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Utility function to update a role while, returning any response (including errors)
func testTokenRoleUpdate(t *testing.T, b *grafanaCloudBackend, s logical.Storage, roleName string, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + roleName,
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return nil, err
	}

	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
	return resp, nil
}

// Utility function to read a role and return any errors
func testTokenRoleRead(t *testing.T, b *grafanaCloudBackend, s logical.Storage, vRole string) (*logical.Response, error) {
	t.Helper()

	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/" + vRole,
		Storage:   s,
	})
}

// Utility function to list roles and return any errors
func testTokenRoleList(t *testing.T, b *grafanaCloudBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   s,
	})
}

// Utility function to delete a role and return any errors
func testTokenRoleDelete(t *testing.T, b *grafanaCloudBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/" + vaultRole,
		Storage:   s,
	})
}
