package scim

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/go-hclog"
	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/common-sdk/pkg/pointers"

	"github.com/openkcm/identity-management-plugins/pkg/config"
	"github.com/openkcm/identity-management-plugins/pkg/utils/errs"
	"github.com/openkcm/identity-management-plugins/pkg/utils/httpclient"
)

const (
	ApplicationSCIMJson = "application/scim+json"

	SearchRequestSchema = "urn:ietf:params:scim:api:messages:2.0:SearchRequest"

	BasePathGroups = "/Groups"
	BasePathUsers  = "/Users"
	PostSearchPath = ".search"

	HeaderAuthorization = "Authorization"
)

var (
	ErrAuthNotImplemented       = errors.New("API Auth not implemented")
	ErrGetUser                  = errors.New("error getting SCIM user")
	ErrListUsers                = errors.New("error listing SCIM users")
	ErrGetGroup                 = errors.New("error getting SCIM group")
	ErrListGroups               = errors.New("error listing SCIM groups")
	ErrHttpCreation             = errors.New("failed to create the http client")
	ErrClientID                 = errors.New("failed to load the client id")
	ErrClientSecret             = errors.New("failed to load the client secret")
	ErrParsingClientCertificate = errors.New("failed to parse client certificate x509 pair")
)

type Client struct {
	logger     hclog.Logger
	httpClient *http.Client
	host       string

	basicAuth *basicAuth
}
type basicAuth struct {
	clientID     string
	clientSecret string
}

func NewClient(cfg *config.Config, logger hclog.Logger) (*Client, error) {
	switch cfg.Auth.Type {
	case commoncfg.BasicSecretType:
		clientId, err := commoncfg.LoadValueFromSourceRef(cfg.Auth.Basic.Username)
		if err != nil {
			return nil, ErrClientID
		}

		clientSecret, err := commoncfg.LoadValueFromSourceRef(cfg.Auth.Basic.Password)
		if err != nil {
			return nil, ErrClientSecret
		}

		return &Client{
			logger:     logger,
			httpClient: &http.Client{},
			host:       cfg.Host,
			basicAuth: &basicAuth{
				clientID:     string(clientId),
				clientSecret: string(clientSecret),
			},
		}, nil
	case commoncfg.MTLSSecretType:
		mtls, err := commoncfg.LoadMTLSConfig(&cfg.Auth.MTLS)
		if err != nil {
			return nil, errs.Wrap(ErrParsingClientCertificate, err)
		}

		return &Client{
			logger: logger,
			httpClient: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: mtls,
				},
			},
			host: cfg.Host,
		}, nil
	default:
		return nil, ErrAuthNotImplemented
	}
}

// GetUser retrieves a SCIM user by its ID.
func (c *Client) GetUser(ctx context.Context, id string) (*User, error) {
	resp, err := c.baseCreateAndExecuteHTTPRequest(ctx, http.MethodGet, BasePathUsers+"/"+id, nil, nil)

	if resp != nil {
		defer func() {
			err := resp.Body.Close()
			if err != nil {
				c.logger.Error("failed to close GetUser response body", "error", err)
			}
		}()
	}

	if err != nil {
		return nil, errs.Wrap(ErrGetUser, err)
	}

	user, err := httpclient.DecodeResponse[User](ctx, "SCIM", resp, http.StatusOK)
	if err != nil {
		return nil, errs.Wrap(ErrGetUser, err)
	}

	return user, nil
}

// ListUsers retrieves a list of SCIM users.
// It supports filtering, pagination (using cursor), and count parameters.
// The useHTTPPost parameter determines whether to use POST method + /.search path for the request.
func (c *Client) ListUsers(
	ctx context.Context,
	method string,
	filter FilterExpression,
	cursor *string,
	count *int,
) (*UserList, error) {
	resp, err := c.createAndExecuteHTTPRequest(ctx, method, BasePathUsers, filter, cursor, count)
	if err != nil {
		return nil, errs.Wrap(ErrListUsers, err)
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			c.logger.Error("failed to close ListUsers response body", "error", err)
		}
	}()

	users, err := httpclient.DecodeResponse[UserList](ctx, "SCIM", resp, http.StatusOK)
	if err != nil {
		return nil, errs.Wrap(ErrListUsers, err)
	}

	return users, nil
}

// GetGroup retrieves a SCIM group by its ID.
func (c *Client) GetGroup(ctx context.Context, id string) (*Group, error) {
	resp, err := c.baseCreateAndExecuteHTTPRequest(ctx, http.MethodGet, BasePathGroups+"/"+id, nil, nil)

	if resp != nil {
		defer func() {
			err := resp.Body.Close()
			if err != nil {
				c.logger.Error("failed to close GetGroup response body", "error", err)
			}
		}()
	}

	if err != nil {
		return nil, errs.Wrap(ErrGetGroup, err)
	}

	group, err := httpclient.DecodeResponse[Group](ctx, "SCIM", resp, http.StatusOK)
	if err != nil {
		return nil, errs.Wrap(ErrGetGroup, err)
	}

	return group, nil
}

// ListGroups retrieves a list of SCIM groups.
// It supports filtering, pagination (using cursor), and count parameters.
// The useHTTPPost parameter determines whether to use POST method + /.search path for the request.
func (c *Client) ListGroups(
	ctx context.Context,
	method string,
	filter FilterExpression,
	cursor *string,
	count *int,
) (*GroupList, error) {
	resp, err := c.createAndExecuteHTTPRequest(ctx, method, BasePathGroups, filter, cursor, count)

	if resp != nil {
		defer func() {
			err := resp.Body.Close()
			if err != nil {
				c.logger.Error("failed to close ListGroups response body", "error", err)
			}
		}()
	}

	if err != nil {
		return nil, errs.Wrap(ErrListGroups, err)
	}

	groups, err := httpclient.DecodeResponse[GroupList](ctx, "SCIM", resp, http.StatusOK)
	if err != nil {
		return nil, errs.Wrap(ErrListGroups, err)
	}

	return groups, nil
}

func (c *Client) doRequest(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodPatch {
		req.Header.Set("Content-Type", ApplicationSCIMJson)
	}

	req.Header.Set("Accept", ApplicationSCIMJson)

	if c.basicAuth != nil {
		basicCreds := []byte(c.basicAuth.clientID + ":" + c.basicAuth.clientSecret)
		req.Header.Set(HeaderAuthorization, "Basic "+base64.RawStdEncoding.EncodeToString(basicCreds))
	}

	return c.httpClient.Do(req)
}

func (c *Client) baseCreateAndExecuteHTTPRequest(
	ctx context.Context,
	method string,
	resourcePath string,
	queryString *string,
	body io.Reader,
) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.host+resourcePath, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if queryString != nil {
		req.URL.RawQuery = *queryString
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}

	return resp, nil
}

// createAndExecuteHTTPRequest create a request to list SCIM resources (users or groups).
// It uses either GET or POST method based on the useHTTPPost parameter.
// It builds the request with the provided filter, cursor, and count parameters.
// For GET method, parameters are added to the query string.
// For POST method, parameters are included in the request body.
func (c *Client) createAndExecuteHTTPRequest(
	ctx context.Context,
	method string,
	basePath string,
	filter FilterExpression,
	cursor *string,
	count *int,
) (*http.Response, error) {
	resourcePath := basePath + "/"

	var (
		body        io.Reader
		queryString string
	)

	if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		resourcePath += PostSearchPath

		var err error

		body, err = buildBodyFromParams(filter, count, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to build request: %w", err)
		}
	} else {
		queryString = buildQueryStringFromParams(filter, cursor, count)
	}

	return c.baseCreateAndExecuteHTTPRequest(ctx, method, resourcePath, pointers.String(queryString), body)
}
