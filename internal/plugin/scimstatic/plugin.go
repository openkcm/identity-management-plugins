// Package scimstatic implements an identity management plugin that serves
// users and groups from a static, SCIM-shaped JSON document given in the
// plugin configuration instead of querying a remote SCIM server.
package scimstatic

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/openkcm/plugin-sdk/pkg/hclog2slog"
	"github.com/samber/oops"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"

	idmangv1 "github.com/openkcm/plugin-sdk/proto/plugin/identity_management/v1"
	configv1 "github.com/openkcm/plugin-sdk/proto/service/common/config/v1"

	"github.com/openkcm/identity-management-plugins/pkg/clients/scim"
	"github.com/openkcm/identity-management-plugins/pkg/config"
	"github.com/openkcm/identity-management-plugins/pkg/utils/errs"
)

var (
	ErrID                     = oops.In("Identity management Plugin")
	ErrNotConfigured          = errors.New("static data not configured")
	ErrNoID                   = errors.New("no id provided")
	ErrGetGroup               = errors.New("failed to get group")
	ErrGetGroupMultipleGroups = errors.New("more than one group")
	ErrGetUsersForGroup       = errors.New("failed to get users for group")
	ErrGetGroupsForUser       = errors.New("failed to get groups for user")
	ErrInvalidData            = errors.New("invalid static data")
	ErrDuplicateID            = errors.New("duplicate id")
)

// Data is the static JSON document served by the plugin.
type Data struct {
	Users  []scim.User  `json:"users"`
	Groups []scim.Group `json:"groups"`
}

// Plugin is an IdentityManagementService backed by static data.
type Plugin struct {
	idmangv1.UnsafeIdentityManagementServiceServer
	configv1.UnsafeConfigServer

	logger    hclog.Logger
	buildInfo string

	mu    sync.RWMutex
	store *store
}

var (
	_ idmangv1.IdentityManagementServiceServer = (*Plugin)(nil)
	_ configv1.ConfigServer                    = (*Plugin)(nil)
)

func NewPlugin(buildInfo string) *Plugin {
	return &Plugin{buildInfo: buildInfo}
}

func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
	slog.SetDefault(hclog2slog.New(logger))
}

func (p *Plugin) Configure(
	_ context.Context,
	req *configv1.ConfigureRequest,
) (*configv1.ConfigureResponse, error) {
	slog.Info("Configuring static scim plugin")

	cfg := config.StaticConfig{}

	err := yaml.Unmarshal([]byte(req.GetYamlConfiguration()), &cfg)
	if err != nil {
		return nil, ErrID.Wrapf(err, "Failed to get yaml Configuration")
	}

	s, err := newStoreFromJSON([]byte(cfg.JSONData))
	if err != nil {
		return nil, ErrID.Wrapf(err, "Failed parsing static data")
	}

	p.mu.Lock()
	p.store = s
	p.mu.Unlock()

	return &configv1.ConfigureResponse{BuildInfo: &p.buildInfo}, nil
}

func (p *Plugin) GetUser(
	_ context.Context,
	request *idmangv1.GetUserRequest,
) (*idmangv1.GetUserResponse, error) {
	s, err := p.getStore()
	if err != nil {
		return nil, err
	}

	user, ok := s.usersByID[request.GetUserId()]
	if !ok {
		return nil, status.New(codes.NotFound, "user not found").Err()
	}

	return &idmangv1.GetUserResponse{User: toUser(user)}, nil
}

func (p *Plugin) GetGroup(
	_ context.Context,
	request *idmangv1.GetGroupRequest,
) (*idmangv1.GetGroupResponse, error) {
	s, err := p.getStore()
	if err != nil {
		return nil, err
	}

	if request.GetGroupName() == "" {
		return nil, errs.Wrap(ErrGetGroup, ErrNoID)
	}

	var matches []*scim.Group

	for _, g := range s.groups {
		if g.DisplayName == request.GetGroupName() {
			matches = append(matches, g)
		}
	}

	switch len(matches) {
	case 0:
		return nil, status.New(codes.NotFound, "group does not exist").Err()
	case 1:
		return &idmangv1.GetGroupResponse{Group: toGroup(matches[0])}, nil
	default:
		return nil, errs.Wrap(ErrGetGroup, ErrGetGroupMultipleGroups)
	}
}

func (p *Plugin) GetAllGroups(
	_ context.Context,
	_ *idmangv1.GetAllGroupsRequest,
) (*idmangv1.GetAllGroupsResponse, error) {
	s, err := p.getStore()
	if err != nil {
		return nil, err
	}

	groups := make([]*idmangv1.Group, len(s.groups))
	for i, g := range s.groups {
		groups[i] = toGroup(g)
	}

	return &idmangv1.GetAllGroupsResponse{Groups: groups}, nil
}

func (p *Plugin) GetUsersForGroup(
	_ context.Context,
	request *idmangv1.GetUsersForGroupRequest,
) (*idmangv1.GetUsersForGroupResponse, error) {
	s, err := p.getStore()
	if err != nil {
		return nil, err
	}

	if request.GetGroupId() == "" {
		return nil, errs.Wrap(ErrGetUsersForGroup, ErrNoID)
	}

	if _, ok := s.groupsByID[request.GetGroupId()]; !ok {
		return nil, status.New(codes.NotFound, "group does not exist").Err()
	}

	var users []*idmangv1.User
	for _, id := range s.membersByGroup[request.GetGroupId()] {
		users = append(users, toUser(s.usersByID[id]))
	}

	return &idmangv1.GetUsersForGroupResponse{Users: users}, nil
}

func (p *Plugin) GetGroupsForUser(
	_ context.Context,
	request *idmangv1.GetGroupsForUserRequest,
) (*idmangv1.GetGroupsForUserResponse, error) {
	s, err := p.getStore()
	if err != nil {
		return nil, err
	}

	if request.GetUserId() == "" {
		return nil, errs.Wrap(ErrGetGroupsForUser, ErrNoID)
	}

	var groups []*idmangv1.Group
	for _, id := range s.groupsByUser[request.GetUserId()] {
		groups = append(groups, toGroup(s.groupsByID[id]))
	}

	return &idmangv1.GetGroupsForUserResponse{Groups: groups}, nil
}

func (p *Plugin) getStore() (*store, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.store == nil {
		return nil, ErrNotConfigured
	}

	return p.store, nil
}

// store is an immutable, indexed view of Data. Membership is the union of
// Group.members and User.groups so the JSON may declare either direction.
type store struct {
	users          []*scim.User
	groups         []*scim.Group
	usersByID      map[string]*scim.User
	groupsByID     map[string]*scim.Group
	membersByGroup map[string][]string // group id -> user ids (ordered)
	groupsByUser   map[string][]string // user id -> group ids (ordered)
}

func newStoreFromJSON(raw []byte) (*store, error) {
	var data Data

	err := json.Unmarshal(raw, &data)
	if err != nil {
		return nil, errs.Wrap(ErrInvalidData, err)
	}

	return newStore(data)
}

func newStore(data Data) (*store, error) {
	s := &store{
		usersByID:      make(map[string]*scim.User, len(data.Users)),
		groupsByID:     make(map[string]*scim.Group, len(data.Groups)),
		membersByGroup: make(map[string][]string),
		groupsByUser:   make(map[string][]string),
	}

	for i := range data.Users {
		u := &data.Users[i]
		if u.ID == "" {
			return nil, errs.Wrapf(ErrInvalidData, "user without id")
		}

		if _, dup := s.usersByID[u.ID]; dup {
			return nil, errs.Wrap(ErrInvalidData, errs.Wrapf(ErrDuplicateID, "user "+u.ID))
		}

		s.usersByID[u.ID] = u
		s.users = append(s.users, u)
	}

	for i := range data.Groups {
		g := &data.Groups[i]
		if g.ID == "" {
			return nil, errs.Wrapf(ErrInvalidData, "group without id")
		}

		if _, dup := s.groupsByID[g.ID]; dup {
			return nil, errs.Wrap(ErrInvalidData, errs.Wrapf(ErrDuplicateID, "group "+g.ID))
		}

		s.groupsByID[g.ID] = g
		s.groups = append(s.groups, g)
	}

	seen := make(map[[2]string]struct{})
	link := func(groupID, userID string) {
		// Ignore references to unknown users/groups, like a SCIM server would not resolve them.
		if _, ok := s.groupsByID[groupID]; !ok {
			return
		}

		if _, ok := s.usersByID[userID]; !ok {
			return
		}

		key := [2]string{groupID, userID}
		if _, ok := seen[key]; ok {
			return
		}

		seen[key] = struct{}{}

		s.membersByGroup[groupID] = append(s.membersByGroup[groupID], userID)
		s.groupsByUser[userID] = append(s.groupsByUser[userID], groupID)
	}

	for _, g := range s.groups {
		for _, m := range g.Members {
			link(g.ID, m.Value)
		}
	}

	for _, u := range s.users {
		for _, g := range u.Groups {
			link(g.Value, u.ID)
		}
	}

	return s, nil
}

func toUser(u *scim.User) *idmangv1.User {
	return &idmangv1.User{
		Id:    u.ID,
		Name:  u.UserName,
		Email: primaryEmail(u),
	}
}

func toGroup(g *scim.Group) *idmangv1.Group {
	return &idmangv1.Group{Id: g.ID, Name: g.DisplayName}
}

func primaryEmail(u *scim.User) string {
	for _, e := range u.Emails {
		if e.Primary {
			return e.Value
		}
	}

	if len(u.Emails) > 0 {
		return u.Emails[0].Value
	}

	return ""
}
