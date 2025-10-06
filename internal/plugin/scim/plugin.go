package scim

import (
	"context"
	"errors"
	"net/http"

	"github.com/hashicorp/go-hclog"
	"github.com/samber/oops"
	"gopkg.in/yaml.v3"

	idmangv1 "github.com/openkcm/plugin-sdk/proto/plugin/identity_management/v1"
	configv1 "github.com/openkcm/plugin-sdk/proto/service/common/config/v1"

	"github.com/openkcm/identity-management-plugins/pkg/clients/scim"
	"github.com/openkcm/identity-management-plugins/pkg/config"
	"github.com/openkcm/identity-management-plugins/pkg/utils/errs"
)

var (
	ErrNoScimClient           = errors.New("no scim client exists")
	ErrPluginCreation         = errors.New("failed to create plugin")
	ErrGetGroup               = errors.New("failed to get group")
	ErrGetAllGroups           = errors.New("failed to get allx group")
	ErrGetGroupNonExistent    = errors.New("group does not existent")
	ErrGetGroupMultipleGroups = errors.New("more than one group")
	ErrGetGroupsForUser       = errors.New("failed to get groups for user")
	ErrGetUsersForGroup       = errors.New("failed to get users for group")
	ErrNoID                   = errors.New("no filter id provided")
)

const defaultFilterAttribute = "displayName"
const defaultUsersFilterAttribute = defaultFilterAttribute
const defaultGroupsFilterAttribute = defaultFilterAttribute

// Plugin is a simple test implementation of KeystoreProviderServer
type Plugin struct {
	idmangv1.UnsafeIdentityManagementServiceServer
	configv1.UnsafeConfigServer

	logger     hclog.Logger
	scimClient *scim.Client
	config     *config.Config
}

var (
	_ idmangv1.IdentityManagementServiceServer = (*Plugin)(nil)
	_ configv1.ConfigServer                    = (*Plugin)(nil)
)

func NewPlugin() *Plugin {
	return &Plugin{}
}

func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

func (p *Plugin) Configure(
	ctx context.Context,
	req *configv1.ConfigureRequest,
) (*configv1.ConfigureResponse, error) {
	p.logger.Info("Configuring plugin")

	p.config = &config.Config{}

	err := yaml.Unmarshal([]byte(req.GetYamlConfiguration()), p.config)
	if err != nil {
		return nil, oops.In("Identity management Plugin").
			Wrapf(err, "Failed to get yaml Configuration")
	}

	client, err := scim.NewClient(p.config, p.logger)
	if err != nil {
		return nil, err
	}

	p.scimClient = client

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) GetGroup(
	ctx context.Context,
	request *idmangv1.GetGroupRequest,
) (*idmangv1.GetGroupResponse, error) {
	if p.scimClient == nil {
		return nil, ErrNoScimClient
	}

	attr := p.params.GroupAttribute
	filter := getFilter(defaultGroupsFilterAttribute, request.GetGroupName(), attr)

	responseGroups, err := p.listGroups(ctx, filter)
	if err != nil {
		return nil, errs.Wrap(ErrGetGroup, err)
	}

	if len(responseGroups) == 0 {
		return nil, errs.Wrap(ErrGetGroup, ErrGetGroupNonExistent)
	} else if len(responseGroups) > 1 {
		return nil, errs.Wrap(ErrGetGroup, ErrGetGroupMultipleGroups)
	}

	return &idmangv1.GetGroupResponse{Group: responseGroups[0]}, nil
}

func (p *Plugin) GetAllGroups(
	ctx context.Context,
	request *idmangv1.GetAllGroupsRequest,
) (*idmangv1.GetAllGroupsResponse, error) {
	groups, err := p.scimClient.ListGroups(ctx, http.MethodGet, scim.NullFilterExpression{}, nil, nil)
	if err != nil {
		return nil, errs.Wrap(ErrGetAllGroups, err)
	}

	responseGroups := make([]*idmangv1.Group, len(groups.Resources))

	for i, group := range groups.Resources {
		responseGroups[i] = &idmangv1.Group{Id: group.ID,
			Name: group.DisplayName}
	}

	return &idmangv1.GetAllGroupsResponse{Groups: responseGroups}, nil
}

func (p *Plugin) GetUsersForGroup(
	ctx context.Context,
	request *idmangv1.GetUsersForGroupRequest,
) (*idmangv1.GetUsersForGroupResponse, error) {
	if p.scimClient == nil {
		return nil, ErrNoScimClient
	}

	attr := p.config.Params.GroupAttribute
	filter := getFilter(defaultGroupsFilterAttribute, request.GetGroupId(), attr)

	if (filter == scim.NullFilterExpression{}) {
		return nil, errs.Wrap(ErrGetUsersForGroup, ErrNoID)
	}

	users, err := p.scimClient.ListUsers(ctx, http.MethodPost, filter, nil, nil)
	if err != nil {
		return nil, errs.Wrap(ErrGetUsersForGroup, err)
	}

	responseUsers := make([]*idmangv1.User, len(users.Resources))

	for i, user := range users.Resources {
		responseUsers[i] = &idmangv1.User{Id: user.ID,
			Name: user.DisplayName}
	}

	return &idmangv1.GetUsersForGroupResponse{Users: responseUsers}, nil
}

func (p *Plugin) GetGroupsForUser(
	ctx context.Context,
	request *idmangv1.GetGroupsForUserRequest,
) (*idmangv1.GetGroupsForUserResponse, error) {
	if p.scimClient == nil {
		return nil, ErrNoScimClient
	}

	attr := p.config.Params.UserAttribute
	filter := getFilter(defaultUsersFilterAttribute, request.GetUserId(), attr)

	responseGroups, err := p.listGroups(ctx, filter)
	if err != nil {
		return nil, errs.Wrap(ErrGetGroupsForUser, err)
	}

	return &idmangv1.GetGroupsForUserResponse{Groups: responseGroups}, nil
}

func (p *Plugin) listGroups(ctx context.Context, filter scim.FilterExpression,
) ([]*idmangv1.Group, error) {
	if (filter == scim.NullFilterExpression{}) {
		return nil, ErrNoID
	}

	groups, err := p.scimClient.ListGroups(ctx, http.MethodPost, filter, nil, nil)
	if err != nil {
		return nil, err
	}

	responseGroups := make([]*idmangv1.Group, len(groups.Resources))

	for i, group := range groups.Resources {
		responseGroups[i] = &idmangv1.Group{Id: group.ID,
			Name: group.DisplayName}
	}

	return responseGroups, nil
}

func getFilter(defaultAttribute, value string, setAttribute *string) scim.FilterExpression {
	if value == "" {
		return scim.NullFilterExpression{}
	}

	filter := scim.FilterComparison{
		Attribute: defaultAttribute,
		Operator:  scim.FilterOperatorEqual,
		Value:     value,
	}

	if setAttribute != nil {
		filter.Attribute = *setAttribute
	}

	return filter
}
