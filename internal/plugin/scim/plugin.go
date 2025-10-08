package scim

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

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

const (
	defaultListMethod = http.MethodPost

	defaultUserListAttribute = "groups.display"

	modifiedByAttribute = "meta.lastModified"
)

var (
	ErrID               = oops.In("Identity management Plugin")
	ErrNoScimClient     = errors.New("no scim client exists")
	ErrGetGroupsForUser = errors.New("failed to get groups for user")
	ErrGetUsersForGroup = errors.New("failed to get users for group")
	ErrNoID             = errors.New("no filter id provided")

	// allFilter is used to get all users or groups
	// by comparing the modified time to the zero timestamp
	allFilter = scim.FilterComparison{
		Attribute: modifiedByAttribute,
		Operator:  scim.FilterOperatorGreater,
		Value:     time.Unix(0, 0).Format(time.RFC3339),
	}
)

// Plugin is a simple test implementation of KeystoreProviderServer
type Plugin struct {
	idmangv1.UnsafeIdentityManagementServiceServer
	configv1.UnsafeConfigServer

	logger     hclog.Logger
	scimClient *scim.Client
	params     config.Params
}

var (
	_ idmangv1.IdentityManagementServiceServer = (*Plugin)(nil)
	_ configv1.ConfigServer                    = (*Plugin)(nil)
)

func NewPlugin() *Plugin {
	return &Plugin{}
}

func (p *Plugin) SetLogger(logger hclog.Logger) {
	slog.SetDefault(hclog2slog.New(logger))
}

func (p *Plugin) Configure(
	ctx context.Context,
	req *configv1.ConfigureRequest,
) (*configv1.ConfigureResponse, error) {
	p.logger.Info("Configuring plugin")

	cfg := config.Config{}

	err := yaml.Unmarshal([]byte(req.GetYamlConfiguration()), &cfg)
	if err != nil {
		return nil, ErrID.Wrapf(err, "Failed to get yaml Configuration")
	}

	p.params = cfg.Params

	hostBytes, err := commoncfg.LoadValueFromSourceRef(cfg.Host)
	if err != nil {
		return nil, ErrID.Wrapf(err, "Failed loading host")
	}

	var host string

	err = json.Unmarshal(hostBytes, &host)
	if err != nil {
		return nil, ErrID.Wrapf(err, "Failed unmarshalling connection")
	}

	client, err := scim.NewClient(host, cfg.Auth, p.logger)
	if err != nil {
		return nil, err
	}

	p.scimClient = client

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) GetAllGroups(
	ctx context.Context,
	_ *idmangv1.GetAllGroupsRequest,
) (*idmangv1.GetAllGroupsResponse, error) {
	groups, err := p.scimClient.ListGroups(ctx, p.getListMethod(), allFilter, nil, nil)
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

	groupID := request.GetGroupId()

	if groupID == "" {
		return nil, errs.Wrap(ErrGetUsersForGroup, ErrNoID)
	}

	var (
		responseUsers        []*idmangv1.User
		getUsersForGroupFunc func(context.Context, string) ([]*idmangv1.User, error)
	)

	if p.params.AllowSearchUsersByGroup {
		getUsersForGroupFunc = p.getUsersForGroupUsingUserList
	} else {
		// If SCIM API does not support filtering users by group attribute,
		// we need to fall back to getting individual users by firstly
		// getting the user IDs from the group members attribute and
		// then getting each user by their ID.
		getUsersForGroupFunc = p.getUsersForGroupUsingGroupMembers
	}

	responseUsers, err := getUsersForGroupFunc(ctx, groupID)
	if err != nil {
		return nil, errs.Wrap(ErrGetUsersForGroup, err)
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

	userID := request.GetUserId()

	if userID == "" {
		return nil, errs.Wrap(ErrGetGroupsForUser, ErrNoID)
	}

	attr := p.params.UserAttribute
	if attr == "" {
		return nil, errs.Wrap(ErrGetGroupsForUser, errors.New("no user attribute configured"))
	}

	filter := scim.FilterComparison{
		Attribute: attr,
		Operator:  scim.FilterOperatorEqual,
		Value:     userID,
	}

	groups, err := p.scimClient.ListGroups(ctx, p.getListMethod(), filter, nil, nil)
	if err != nil {
		return nil, errs.Wrap(ErrGetGroupsForUser, err)
	}

	responseGroups := make([]*idmangv1.Group, len(groups.Resources))

	for i, group := range groups.Resources {
		responseGroups[i] = &idmangv1.Group{Name: group.DisplayName}
	}

	return &idmangv1.GetGroupsForUserResponse{Groups: responseGroups}, nil
}

func (p *Plugin) getListMethod() string {
	if p.params.ListMethod != "" {
		return p.params.ListMethod
	}

	return defaultListMethod
}

func (p *Plugin) getUserListAttribute() string {
	if p.params.GroupAttribute != "" {
		return p.params.GroupAttribute
	}

	return defaultUserListAttribute
}

func (p *Plugin) getUsersForGroupUsingUserList(ctx context.Context, groupID string) ([]*idmangv1.User, error) {
	responseUsers := make([]*idmangv1.User, 0)

	filter := scim.FilterComparison{
		Attribute: p.getUserListAttribute(),
		Operator:  scim.FilterOperatorEqual,
		Value:     groupID,
	}

	users, err := p.scimClient.ListUsers(ctx, p.getListMethod(), filter, nil, nil)
	if err != nil {
		return nil, errs.Wrap(ErrGetUsersForGroup, err)
	}

	for _, user := range users.Resources {
		responseUsers = append(responseUsers, &idmangv1.User{
			Id:   user.ID,
			Name: getPrimaryEmailAddress(&user),
		})
	}

	return responseUsers, nil
}

func (p *Plugin) getUsersForGroupUsingGroupMembers(ctx context.Context, groupID string) ([]*idmangv1.User, error) {
	responseUsers := make([]*idmangv1.User, 0)

	group, err := p.scimClient.GetGroup(ctx, groupID, p.params.GroupMembersAttribute)
	if err != nil {
		return nil, errs.Wrap(ErrGetUsersForGroup, err)
	}

	for _, member := range group.Members {
		user, err := p.scimClient.GetUser(ctx, member.Value)
		if err != nil {
			return nil, errs.Wrap(ErrGetUsersForGroup, err)
		}

		responseUsers = append(responseUsers, &idmangv1.User{
			Id:   user.ID,
			Name: getPrimaryEmailAddress(user),
		})
	}

	return responseUsers, nil
}

func getPrimaryEmailAddress(user *scim.User) string {
	for _, email := range user.Emails {
		if email.Primary {
			return email.Value
		}
	}

	// Fallback to the first email if no primary is set
	if len(user.Emails) > 0 {
		return user.Emails[0].Value
	}

	return ""
}
