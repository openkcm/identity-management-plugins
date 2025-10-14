package scim

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/hashicorp/go-hclog"
	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/plugin-sdk/pkg/hclog2slog"
	"github.com/samber/oops"
	"gopkg.in/yaml.v3"

	idmangv1 "github.com/openkcm/plugin-sdk/proto/plugin/identity_management/v1"
	configv1 "github.com/openkcm/plugin-sdk/proto/service/common/config/v1"

	"github.com/openkcm/identity-management-plugins/pkg/clients/scim"
	"github.com/openkcm/identity-management-plugins/pkg/config"
	"github.com/openkcm/identity-management-plugins/pkg/utils/errs"
)

var (
	ErrID               = oops.In("Identity management Plugin")
	ErrNoScimClient     = errors.New("no scim client exists")
	ErrPluginCreation   = errors.New("failed to create plugin")
	ErrGetGroupsForUser = errors.New("failed to get groups for user")
	ErrGetUsersForGroup = errors.New("failed to get users for group")
	ErrNoID             = errors.New("no filter id provided")
)

const defaultFilterAttribute = "displayName"
const defaultUsersFilterAttribute = defaultFilterAttribute
const defaultGroupsFilterAttribute = defaultFilterAttribute

type Params struct {
	GroupAttribute string
	UserAttribute  string
}

// Plugin is a simple test implementation of KeystoreProviderServer
type Plugin struct {
	idmangv1.UnsafeIdentityManagementServiceServer
	configv1.UnsafeConfigServer

	logger     hclog.Logger
	scimClient *scim.Client
	params     Params
}

var (
	_ idmangv1.IdentityManagementServiceServer = (*Plugin)(nil)
	_ configv1.ConfigServer                    = (*Plugin)(nil)
)

func NewPlugin() *Plugin {
	return &Plugin{}
}

func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger // Keep a copy of the logger for client creation
	slog.SetDefault(hclog2slog.New(logger))
}

func (p *Plugin) Configure(
	ctx context.Context,
	req *configv1.ConfigureRequest,
) (*configv1.ConfigureResponse, error) {
	slog.Info("Configuring plugin")

	cfg := config.Config{}

	err := yaml.Unmarshal([]byte(req.GetYamlConfiguration()), &cfg)
	if err != nil {
		return nil, ErrID.Wrapf(err, "Failed to get yaml Configuration")
	}

	groupAttrBytes, err := commoncfg.LoadValueFromSourceRef(cfg.Params.GroupAttribute)
	if err != nil {
		return nil, ErrID.Wrapf(err, "Failed loading host")
	}

	var groupAttr string

	err = json.Unmarshal(groupAttrBytes, &groupAttr)
	if err != nil {
		return nil, ErrID.Wrapf(err, "Failed unmarshalling group attribute")
	}

	userAttrBytes, err := commoncfg.LoadValueFromSourceRef(cfg.Params.UserAttribute)
	if err != nil {
		return nil, ErrID.Wrapf(err, "Failed loading user attribute")
	}

	var userAttr string

	err = json.Unmarshal(userAttrBytes, &userAttr)
	if err != nil {
		return nil, ErrID.Wrapf(err, "Failed unmarshalling user attribute")
	}

	p.params = Params{GroupAttribute: groupAttr, UserAttribute: userAttr}

	client, err := scim.NewClient(cfg.Host, cfg.Auth, p.logger)
	if err != nil {
		return nil, err
	}

	p.scimClient = client

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) GetAllGroups(
	ctx context.Context,
	request *idmangv1.GetAllGroupsRequest,
) (*idmangv1.GetAllGroupsResponse, error) {
	groups, err := p.scimClient.ListGroups(ctx, http.MethodGet, scim.NullFilterExpression{}, nil, nil)
	if err != nil {
		return nil, errs.Wrap(ErrGetGroupsForUser, err)
	}

	responseGroups := make([]*idmangv1.Group, len(groups.Resources))

	for i, group := range groups.Resources {
		responseGroups[i] = &idmangv1.Group{Name: group.DisplayName}
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

	attr := p.params.GroupAttribute
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
		responseUsers[i] = &idmangv1.User{Name: user.DisplayName}
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

	attr := p.params.UserAttribute
	filter := getFilter(defaultUsersFilterAttribute, request.GetUserId(), attr)

	if (filter == scim.NullFilterExpression{}) {
		return nil, errs.Wrap(ErrGetGroupsForUser, ErrNoID)
	}

	groups, err := p.scimClient.ListGroups(ctx, http.MethodPost, filter, nil, nil)
	if err != nil {
		return nil, errs.Wrap(ErrGetGroupsForUser, err)
	}

	responseGroups := make([]*idmangv1.Group, len(groups.Resources))

	for i, group := range groups.Resources {
		responseGroups[i] = &idmangv1.Group{Name: group.DisplayName}
	}

	return &idmangv1.GetGroupsForUserResponse{Groups: responseGroups}, nil
}

func getFilter(defaultAttribute, value string, setAttribute string) scim.FilterExpression {
	if value == "" {
		return scim.NullFilterExpression{}
	}

	filter := scim.FilterComparison{
		Attribute: defaultAttribute,
		Operator:  scim.FilterOperatorEqual,
		Value:     value,
	}

	if setAttribute != "" {
		filter.Attribute = setAttribute
	}

	return filter
}
