package scimstatic_test

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"

	idmangv1 "github.com/openkcm/plugin-sdk/proto/plugin/identity_management/v1"
	configv1 "github.com/openkcm/plugin-sdk/proto/service/common/config/v1"

	plugin "github.com/openkcm/identity-management-plugins/internal/plugin/scimstatic"
)

const testData = `{
  "users": [
    {"id": "u1", "userName": "alice", "emails": [{"value": "alice-2@example.com"}, {"value": "alice@example.com", "primary": true}],
     "groups": [{"value": "g2", "display": "Auditors"}]},
    {"id": "u2", "userName": "bob", "emails": [{"value": "bob@example.com"}]},
    {"id": "u3", "userName": "carol"}
  ],
  "groups": [
    {"id": "g1", "displayName": "KeyAdmin", "members": [{"value": "u1"}, {"value": "u2"}, {"value": "unknown"}]},
    {"id": "g2", "displayName": "Auditors"},
    {"id": "g3", "displayName": "Dup"},
    {"id": "g4", "displayName": "Dup"}
  ]
}`

func yamlConfig(t *testing.T, data string) string {
	t.Helper()

	out, err := yaml.Marshal(map[string]string{"json_data": data})
	assert.NoError(t, err)

	return string(out)
}

func setup(t *testing.T) *plugin.Plugin {
	t.Helper()

	p := plugin.NewPlugin("{}")
	p.SetLogger(hclog.New(&hclog.LoggerOptions{Level: hclog.Error}))

	_, err := p.Configure(t.Context(), &configv1.ConfigureRequest{YamlConfiguration: yamlConfig(t, testData)})
	assert.NoError(t, err)

	return p
}

func TestNotConfigured(t *testing.T) {
	p := plugin.NewPlugin("{}")

	_, err := p.GetUser(t.Context(), &idmangv1.GetUserRequest{UserId: "u1"})
	assert.ErrorIs(t, err, plugin.ErrNotConfigured)

	_, err = p.GetAllGroups(t.Context(), &idmangv1.GetAllGroupsRequest{})
	assert.ErrorIs(t, err, plugin.ErrNotConfigured)
}

func TestConfigure(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		ok   bool
	}{
		{"valid data", yamlConfig(t, testData), true},
		{"block scalar", "json_data: |\n  {\"users\": [{\"id\": \"a\"}]}\n", true},
		{"empty object", yamlConfig(t, "{}"), true},
		{"invalid json", yamlConfig(t, "{nope"), false},
		{"missing data", "", false},
		{"data not a string", "json_data:\n  value: x\n", false},
		{"duplicate user id", yamlConfig(t, `{"users":[{"id":"a"},{"id":"a"}]}`), false},
		{"user without id", yamlConfig(t, `{"users":[{"userName":"x"}]}`), false},
		{"duplicate group id", yamlConfig(t, `{"groups":[{"id":"a"},{"id":"a"}]}`), false},
		{"bad yaml", ":::", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := plugin.NewPlugin("{}")
			resp, err := p.Configure(t.Context(), &configv1.ConfigureRequest{YamlConfiguration: tt.yaml})

			if tt.ok {
				assert.NoError(t, err)
				assert.Equal(t, "{}", resp.GetBuildInfo())
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestGetUser(t *testing.T) {
	p := setup(t)

	resp, err := p.GetUser(t.Context(), &idmangv1.GetUserRequest{UserId: "u1"})
	assert.NoError(t, err)
	assert.Equal(t, &idmangv1.User{Id: "u1", Name: "alice", Email: "alice@example.com"}, resp.GetUser())

	// falls back to the first email when none is primary
	resp, err = p.GetUser(t.Context(), &idmangv1.GetUserRequest{UserId: "u2"})
	assert.NoError(t, err)
	assert.Equal(t, "bob@example.com", resp.GetUser().GetEmail())

	resp, err = p.GetUser(t.Context(), &idmangv1.GetUserRequest{UserId: "u3"})
	assert.NoError(t, err)
	assert.Empty(t, resp.GetUser().GetEmail())

	_, err = p.GetUser(t.Context(), &idmangv1.GetUserRequest{UserId: "nope"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestGetGroup(t *testing.T) {
	p := setup(t)

	resp, err := p.GetGroup(t.Context(), &idmangv1.GetGroupRequest{GroupName: "KeyAdmin"})
	assert.NoError(t, err)
	assert.Equal(t, &idmangv1.Group{Id: "g1", Name: "KeyAdmin"}, resp.GetGroup())

	_, err = p.GetGroup(t.Context(), &idmangv1.GetGroupRequest{GroupName: "nope"})
	assert.Equal(t, codes.NotFound, status.Code(err))

	_, err = p.GetGroup(t.Context(), &idmangv1.GetGroupRequest{GroupName: "Dup"})
	assert.ErrorIs(t, err, plugin.ErrGetGroupMultipleGroups)

	_, err = p.GetGroup(t.Context(), &idmangv1.GetGroupRequest{})
	assert.ErrorIs(t, err, plugin.ErrNoID)
}

func TestGetAllGroups(t *testing.T) {
	p := setup(t)

	resp, err := p.GetAllGroups(t.Context(), &idmangv1.GetAllGroupsRequest{})
	assert.NoError(t, err)
	assert.Len(t, resp.GetGroups(), 4)
	assert.Equal(t, "g1", resp.GetGroups()[0].GetId())
}

func TestGetUsersForGroup(t *testing.T) {
	p := setup(t)

	// members declared on the group (unknown member ignored)
	resp, err := p.GetUsersForGroup(t.Context(), &idmangv1.GetUsersForGroupRequest{GroupId: "g1"})
	assert.NoError(t, err)
	assert.Len(t, resp.GetUsers(), 2)
	assert.Equal(t, "alice", resp.GetUsers()[0].GetName())
	assert.Equal(t, "bob", resp.GetUsers()[1].GetName())

	// membership declared only on the user
	resp, err = p.GetUsersForGroup(t.Context(), &idmangv1.GetUsersForGroupRequest{GroupId: "g2"})
	assert.NoError(t, err)
	assert.Len(t, resp.GetUsers(), 1)
	assert.Equal(t, "u1", resp.GetUsers()[0].GetId())

	// group without members
	resp, err = p.GetUsersForGroup(t.Context(), &idmangv1.GetUsersForGroupRequest{GroupId: "g3"})
	assert.NoError(t, err)
	assert.Empty(t, resp.GetUsers())

	_, err = p.GetUsersForGroup(t.Context(), &idmangv1.GetUsersForGroupRequest{GroupId: "nope"})
	assert.Equal(t, codes.NotFound, status.Code(err))

	_, err = p.GetUsersForGroup(t.Context(), &idmangv1.GetUsersForGroupRequest{})
	assert.ErrorIs(t, err, plugin.ErrNoID)
}

func TestGetGroupsForUser(t *testing.T) {
	p := setup(t)

	// union of both membership directions, no duplicates
	resp, err := p.GetGroupsForUser(t.Context(), &idmangv1.GetGroupsForUserRequest{UserId: "u1"})
	assert.NoError(t, err)
	assert.Len(t, resp.GetGroups(), 2)
	assert.Equal(t, "g1", resp.GetGroups()[0].GetId())
	assert.Equal(t, "g2", resp.GetGroups()[1].GetId())

	resp, err = p.GetGroupsForUser(t.Context(), &idmangv1.GetGroupsForUserRequest{UserId: "u3"})
	assert.NoError(t, err)
	assert.Empty(t, resp.GetGroups())

	_, err = p.GetGroupsForUser(t.Context(), &idmangv1.GetGroupsForUserRequest{})
	assert.ErrorIs(t, err, plugin.ErrNoID)
}
