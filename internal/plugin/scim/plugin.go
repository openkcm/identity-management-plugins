package scim

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/samber/oops"
	"gopkg.in/yaml.v3"

	idmangv1 "github.com/openkcm/plugin-sdk/proto/plugin/identity_management/v1"
	configv1 "github.com/openkcm/plugin-sdk/proto/service/common/config/v1"

	"github.com/openkcm/identity-management-plugins/pkg/clients/scim"
	"github.com/openkcm/identity-management-plugins/pkg/utils/errs"
)

var (
	ErrNoScimClient     = errors.New("no scim client exists")
	ErrPluginCreation   = errors.New("failed to create plugin")
	ErrGetGroupsForUser = errors.New("failed to get groups for user")
	ErrGetUsersForGroup = errors.New("failed to get users for group")
	ErrNoID             = errors.New("no filter id provided")
)

const defaultFilterAttribute = "displayName"
const defaultUsersFilterAttribute = defaultFilterAttribute
const defaultGroupsFilterAttribute = defaultFilterAttribute

// Plugin is a simple test implementation of KeystoreProviderServer
type Plugin struct {
	idmangv1.UnsafeIdentityManagementServiceServer
	configv1.UnsafeConfigServer

	logger        hclog.Logger
	scimClient    *scim.Client
	requestParams RequestParams
}

type RequestParams struct {
	GroupAttribute *string `json:"groupattribute"`
	UserAttribute  *string `json:"userattribute"`
}

type Config struct {
	ConnectCfg    scim.APIParams `json:"connectcfg"`
	RequestParams RequestParams  `json:"requestparams"`
}

type Required struct {
	CredentialFile string `yaml:"credentialfile"` //nolint:tagliatelle
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

	var cfgReq Required

	err := yaml.Unmarshal([]byte(req.GetYamlConfiguration()), &cfgReq)
	if err != nil {
		return nil, oops.In("Identity management Plugin").
			Wrapf(err, "Failed to get yaml Configuration")
	}

	cfg, err := buildConfigFromRequest(&cfgReq)
	if err != nil {
		return nil, oops.In("Identity management Plugin").
			Wrapf(err, "Failed to build config")
	}

	client, err := scim.NewClientFromAPI(ctx, cfg.ConnectCfg)
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
	groups, err := p.scimClient.ListGroups(ctx, false, scim.NullFilterExpression{}, nil, nil)
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

	filter := getFilter(defaultGroupsFilterAttribute, request.GetGroupId(),
		p.requestParams.GroupAttribute)

	if (filter == scim.NullFilterExpression{}) {
		return nil, errs.Wrap(ErrGetUsersForGroup, ErrNoID)
	}

	users, err := p.scimClient.ListUsers(ctx, true, filter, nil, nil)
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

	filter := getFilter(defaultUsersFilterAttribute, request.GetUserId(),
		p.requestParams.UserAttribute)

	if (filter == scim.NullFilterExpression{}) {
		return nil, errs.Wrap(ErrGetGroupsForUser, ErrNoID)
	}

	groups, err := p.scimClient.ListGroups(ctx, true, filter, nil, nil)
	if err != nil {
		return nil, errs.Wrap(ErrGetGroupsForUser, err)
	}

	responseGroups := make([]*idmangv1.Group, len(groups.Resources))

	for i, group := range groups.Resources {
		responseGroups[i] = &idmangv1.Group{Name: group.DisplayName}
	}

	return &idmangv1.GetGroupsForUserResponse{Groups: responseGroups}, nil
}

func buildConfigFromRequest(cfgReq *Required) (Config, error) {
	data, err := os.ReadFile(cfgReq.CredentialFile)
	if err != nil {
		return Config{}, err
	}

	var cfg Config

	err = json.Unmarshal(data, &cfg)
	if err != nil {
		return Config{}, err
	}

	return cfg, nil
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
