package testplugin_test

import (
	"context"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"

	idmangv1 "github.com/openkcm/plugin-sdk/proto/plugin/identity_management/v1"

	tp "github.com/openkcm/identity-management-plugins/internal/plugin/test"
)

func setupTest() *tp.TestPlugin {
	p := tp.NewTestPlugin()
	p.SetLogger(hclog.New(&hclog.LoggerOptions{Level: hclog.Error}))

	return p
}

func TestGetGroup(t *testing.T) {
	p := setupTest()

	responseMsg, err := p.GetGroup(context.Background(),
		&idmangv1.GetGroupRequest{})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	assert.Equal(
		t,
		&idmangv1.GetGroupResponse{},
		responseMsg,
	)
}

func TestGetAllGroups(t *testing.T) {
	p := setupTest()

	responseMsg, err := p.GetAllGroups(context.Background(),
		&idmangv1.GetAllGroupsRequest{})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	assert.Equal(
		t,
		&idmangv1.GetAllGroupsResponse{},
		responseMsg,
	)
}

func TestGetUsersForGroup(t *testing.T) {
	p := setupTest()

	responseMsg, err := p.GetUsersForGroup(context.Background(),
		&idmangv1.GetUsersForGroupRequest{})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	assert.Equal(
		t,
		&idmangv1.GetUsersForGroupResponse{},
		responseMsg,
	)
}

func TestGetGroupsForUser(t *testing.T) {
	p := setupTest()

	responseMsg, err := p.GetGroupsForUser(context.Background(),
		&idmangv1.GetGroupsForUserRequest{})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	assert.Equal(
		t,
		&idmangv1.GetGroupsForUserResponse{},
		responseMsg,
	)
}

func TestNewTestPlugin(t *testing.T) {
	p := setupTest()
	assert.NotNil(t, p)
}
