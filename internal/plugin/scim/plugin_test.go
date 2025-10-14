package scim_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openkcm/common-sdk/pkg/pointers"
	"github.com/stretchr/testify/assert"

	idmangv1 "github.com/openkcm/plugin-sdk/proto/plugin/identity_management/v1"

	plugin "github.com/openkcm/identity-management-plugins/internal/plugin/scim"
	"github.com/openkcm/identity-management-plugins/pkg/clients/scim"
)

const (
	NonExistentField = "Non-existent"
	GetUserResponse  = `{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",` +
		`"meta":{"created":"2020-04-10T11:29:36Z","lastModified":"2021-05-18T15:18:00Z",` +
		`"location":"https://dummy.domain.com/scim/Users/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",` +
		`"resourceType":"User", "groups.cnt":0}, "schemas":["urn:ietf:params:scim:schemas:core:2.0:User",` +
		`"urn:ietf:params:scim:schemas:extension:comp:2.0:User"], "userName":"cloudanalyst",` +
		`"name":{"familyName":"Analyst", "givenName":"Cloud"}, "displayName":"None", "userType":"employee",` +
		`"active":true, "emails":[{"value":"cloud.analyst@example.com", "primary":true}],` +
		`"groups":[{"value":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "display":"CloudAnalyst"}],` +
		`"urn:ietf:params:scim:schemas:extension:comp:2.0:User":` +
		`{"emails":[{"verified":false, "value":"cloud.analyst@example.com", "primary":true}],` +
		`"sourceSystem":0, "userUuid":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",` +
		`"mailVerified":false, "userId":"P000011", "status":"active",` +
		`"passwordDetails":{"failedLoginAttempts":0, "setTime":"2020-04-10T11:29:36Z",` +
		`"status":"initial", "policy":"https://dummy.domain.com/policy/passwords/comp/web/1.1"}}}`
	ListUsersResponse = `{"Resources":[` + GetUserResponse + `],` +
		`"totalResults":1, "startIndex": 1, "itemsPerPage":1,` +
		`"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"]}`

	GetGroupResponse = `{"id":"16e720aa-a009-4949-9bf9-aaaaaaaaaaaa",` +
		`"meta":{"created":"2020-11-12T14:55:12Z","lastModified":"2021-03-31T14:56:01Z",` +
		`"location":"https://dummy.domain.com.com/scim/Groups/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",` +
		`"version":"f5c7bafe-b86f-4741-a35a-b53fe07b25e6","resourceType":"Group"},` +
		`"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group",` +
		`"urn:comp:cloud:scim:schemas:extension:custom:2.0:Group"],"displayName":"KeyAdmin",` +
		`"members":[{"value":"11111111-bbbb-cccc-dddd-ffffffffffff","type":"User"}],` +
		`"urn:comp:cloud:scim:schemas:extension:custom:2.0:Group":{"name":"KeyAdmin",` +
		`"additionalId":"5f079f17cbf5f51daaaaaaaa","description":""}}`
	ListGroupsResponse = `{"Resources":[` + GetGroupResponse + `],` +
		`"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],` +
		`"totalResults":1,"itemsPerPage":1,"startIndex":1}`
	EmptyResponse = `{"Resources":[],` +
		`"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],` +
		`"totalResults":0,"itemsPerPage":1,"startIndex":0}`
)

var NonExistentFieldPtr *string = pointers.To(NonExistentField)

func setupTest(t *testing.T, url string,
	groupFilterAttribute, userFilterAttribute string) *plugin.Plugin {
	t.Helper()

	p := plugin.NewPlugin()
	p.SetTestClient(t, url, groupFilterAttribute, userFilterAttribute)
	assert.NotNil(t, p)

	return p
}

func TestNoScimClient(t *testing.T) {
	p := plugin.NewPlugin()

	groupRequest := idmangv1.GetUsersForGroupRequest{}
	_, err := p.GetUsersForGroup(t.Context(), &groupRequest)

	assert.Error(t, err)
	assert.ErrorIs(t, err, plugin.ErrNoScimClient)

	userRequest := idmangv1.GetGroupsForUserRequest{}
	_, err = p.GetGroupsForUser(t.Context(), &userRequest)

	assert.Error(t, err)
	assert.ErrorIs(t, err, plugin.ErrNoScimClient)
}

func TestGetAllGroups(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(ListGroupsResponse))

		assert.NoError(t, err)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tests := []struct {
		name              string
		serverUrl         string
		testNumGroups     int
		testGroupId       string
		testGroupName     string
		testExpectedError *error
	}{
		{
			name:              "Bad Server",
			serverUrl:         "badurl",
			testNumGroups:     0,
			testGroupId:       "",
			testGroupName:     "",
			testExpectedError: &scim.ErrListGroups,
		},
		{
			name:              "Good request",
			serverUrl:         server.URL,
			testNumGroups:     1,
			testGroupId:       "16e720aa-a009-4949-9bf9-aaaaaaaaaaaa",
			testGroupName:     "KeyAdmin",
			testExpectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := setupTest(t, tt.serverUrl, "", "")

			responseMsg, err := p.GetAllGroups(t.Context(),
				&idmangv1.GetAllGroupsRequest{})

			if tt.testExpectedError == nil {
				assert.NoError(t, err)
				assert.Len(t, responseMsg.GetGroups(), tt.testNumGroups)

				if tt.testNumGroups > 0 {
					assert.Equal(
						t,
						&idmangv1.GetAllGroupsResponse{
							Groups: []*idmangv1.Group{{
								Id:   tt.testGroupId,
								Name: tt.testGroupName}},
						},
						responseMsg,
					)
				}
			} else {
				assert.ErrorIs(t, err, *tt.testExpectedError)
			}
		})
	}
}

func TestGetUsersForGroup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		assert.NoError(t, err)

		// Quick and dirty mock server filtering. Fine since we aren't testing server here
		reqStr := string(bodyBytes)
		if strings.Contains(reqStr, NonExistentField) {
			_, err = w.Write([]byte(EmptyResponse))
		} else {
			_, err = w.Write([]byte(ListUsersResponse))
		}

		assert.NoError(t, err)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tests := []struct {
		name                 string
		serverUrl            string
		groupFilterAttribute string
		groupFilterValue     *string
		testNumUsers         int
		testUserName         string
		testUserId           string
		testExpectedError    *error
	}{
		{
			name:                 "Bad Server",
			serverUrl:            "badurl",
			groupFilterAttribute: "displayName",
			groupFilterValue:     pointers.To("None"),
			testNumUsers:         0,
			testUserName:         "",
			testUserId:           "",
			testExpectedError:    &scim.ErrListUsers,
		},
		{
			name:                 "Good request",
			serverUrl:            server.URL,
			groupFilterAttribute: "displayName",
			groupFilterValue:     pointers.To("None"),
			testNumUsers:         1,
			testUserName:         "None",
			testUserId:           "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			testExpectedError:    nil,
		},
		{
			name:                 "Non-existent filter value",
			serverUrl:            server.URL,
			groupFilterAttribute: "displayName",
			groupFilterValue:     NonExistentFieldPtr,
			testNumUsers:         0,
			testUserName:         "",
			testUserId:           "",
			testExpectedError:    nil,
		},
		{
			name:                 "Non-existent filter attribute",
			serverUrl:            server.URL,
			groupFilterAttribute: NonExistentField,
			groupFilterValue:     pointers.To("None"),
			testNumUsers:         0,
			testUserName:         "",
			testUserId:           "",
			testExpectedError:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := setupTest(t, tt.serverUrl, tt.groupFilterAttribute, "")

			var request = idmangv1.GetUsersForGroupRequest{}
			if tt.groupFilterValue != nil {
				request.GroupId = *tt.groupFilterValue
			}

			responseMsg, err := p.GetUsersForGroup(t.Context(), &request)

			if tt.testExpectedError == nil {
				assert.NoError(t, err)
				assert.Len(t, responseMsg.GetUsers(), tt.testNumUsers)

				if tt.testNumUsers > 0 {
					assert.Equal(
						t,
						&idmangv1.GetUsersForGroupResponse{
							Users: []*idmangv1.User{{
								Id:   tt.testUserId,
								Name: tt.testUserName},
							},
						},
						responseMsg,
					)
				}
			} else {
				assert.ErrorIs(t, err, *tt.testExpectedError)
			}
		})
	}
}

func TestGetGroupsForUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		assert.NoError(t, err)

		// Quick and dirty mock server filtering. Fine since we aren't testing server here
		reqStr := string(bodyBytes)
		if strings.Contains(reqStr, NonExistentField) {
			_, err = w.Write([]byte(EmptyResponse))
		} else {
			_, err = w.Write([]byte(ListGroupsResponse))
		}

		assert.NoError(t, err)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tests := []struct {
		name                string
		serverUrl           string
		userFilterAttribute string
		userFilterValue     *string
		testNumGroups       int
		testGroupId         string
		testGroupName       string
		testExpectedError   *error
	}{
		{
			name:                "Bad Server",
			serverUrl:           "badurl",
			userFilterAttribute: "displayName",
			userFilterValue:     pointers.To("None"),
			testNumGroups:       0,
			testGroupId:         "",
			testGroupName:       "",
			testExpectedError:   &scim.ErrListGroups,
		},
		{
			name:                "Good request",
			serverUrl:           server.URL,
			userFilterAttribute: "displayName",
			userFilterValue:     pointers.To("None"),
			testNumGroups:       1,
			testGroupId:         "16e720aa-a009-4949-9bf9-aaaaaaaaaaaa",
			testGroupName:       "KeyAdmin",
			testExpectedError:   nil,
		},
		{
			name:                "Non-existent filter value",
			serverUrl:           server.URL,
			userFilterAttribute: "displayName",
			userFilterValue:     NonExistentFieldPtr,
			testNumGroups:       0,
			testGroupId:         "",
			testGroupName:       "",
			testExpectedError:   nil,
		},
		{
			name:                "Non-existent filter attribute",
			serverUrl:           server.URL,
			userFilterAttribute: NonExistentField,
			userFilterValue:     pointers.To("None"),
			testNumGroups:       0,
			testGroupId:         "",
			testGroupName:       "",
			testExpectedError:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := setupTest(t, tt.serverUrl, "", tt.userFilterAttribute)

			var userFilterValue = idmangv1.GetGroupsForUserRequest{}
			if tt.userFilterValue != nil {
				userFilterValue.UserId = *tt.userFilterValue
			}

			responseMsg, err := p.GetGroupsForUser(t.Context(),
				&userFilterValue)

			if tt.testExpectedError == nil {
				assert.NoError(t, err)
				assert.Len(t, responseMsg.GetGroups(), tt.testNumGroups)

				if tt.testNumGroups > 0 {
					assert.Equal(
						t,
						&idmangv1.GetGroupsForUserResponse{
							Groups: []*idmangv1.Group{{
								Id:   tt.testGroupId,
								Name: tt.testGroupName}},
						},
						responseMsg,
					)
				}
			} else {
				assert.ErrorIs(t, err, *tt.testExpectedError)
			}
		})
	}
}

func TestNewPlugin(t *testing.T) {
	p := setupTest(t, "", "", "")
	assert.NotNil(t, p)
}
