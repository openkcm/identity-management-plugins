package scim

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/go-hclog"
	"github.com/openkcm/common-sdk/pkg/commoncfg"
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
	ErrGetUser                  = errors.New("error getting SCIM user")
	ErrListUsers                = errors.New("error listing SCIM users")
	ErrGetGroup                 = errors.New("error getting SCIM group")
	ErrListGroups               = errors.New("error listing SCIM groups")
	ErrAuthParams               = errors.New("must provide client secret or TLS config")
	ErrHttpCreation             = errors.New("failed to create the http client")
	ErrClientID                 = errors.New("failed to load the client id")
	ErrClientSecret             = errors.New("failed to load the client secret")
	ErrParsingClientCertificate = errors.New("failed to parse client certificate x509 pair")
)

type Client struct {
	logger     hclog.Logger
	httpClient *http.Client

	scimHost  string
	basicAuth *basicAuth
}
type basicAuth struct {
	clientID     string
	clientSecret string
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

func NewClientFromAPI(cfg *config.Config, logger hclog.Logger) (*Client, error) {
	clientId, err := commoncfg.LoadValueFromSourceRef(cfg.Auth.Credentials.ClientID)
	if err != nil {
		return nil, ErrClientID
	}

	if cfg.Auth.Credentials.ClientSecret != nil {
		clientSecret, err := commoncfg.LoadValueFromSourceRef(*cfg.Auth.Credentials.ClientSecret)
		if err != nil {
			return nil, ErrClientSecret
		}

		return &Client{
			logger:     logger,
			httpClient: &http.Client{},
			scimHost:   cfg.Host,
			basicAuth: &basicAuth{
				clientID:     string(clientId),
				clientSecret: string(clientSecret),
			},
		}, nil
	}

	if cfg.Auth.MTLS != nil {
		cert, err := commoncfg.LoadMTLSClientCertificate(cfg.Auth.MTLS)
		if err != nil {
			return nil, ErrParsingClientCertificate
		}
		return &Client{
			logger: logger,
			httpClient: &http.Client{
				Transport: &http.Transport{ // client cert auth
					TLSClientConfig: &tls.Config{
						Certificates: []tls.Certificate{*cert},
					},
				},
			},
			scimHost: cfg.Host,
		}, nil
	}

	return nil, ErrHttpCreation
}

// GetUser retrieves a SCIM user by its ID.
func (c *Client) GetUser(ctx context.Context, id string) (*User, error) {
	resourcePath := BasePathUsers + "/" + id
	resp, err := c.makeAPIRequest(ctx, http.MethodGet, resourcePath, nil, nil)

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
	useHTTPPost bool,
	filter FilterExpression,
	cursor *string,
	count *int,
) (*UserList, error) {
	resp, err := c.makeListRequest(ctx, useHTTPPost, BasePathUsers, filter, cursor, count)
	if resp != nil {
		defer func() {
			err := resp.Body.Close()
			if err != nil {
				c.logger.Error("failed to close ListUsers response body", "error", err)
			}
		}()
	}

	if err != nil {
		return nil, errs.Wrap(ErrListUsers, err)
	}

	users, err := httpclient.DecodeResponse[UserList](ctx, "SCIM", resp, http.StatusOK)
	if err != nil {
		return nil, errs.Wrap(ErrListUsers, err)
	}

	return users, nil
}

// GetGroup retrieves a SCIM group by its ID.
func (c *Client) GetGroup(ctx context.Context, id string) (*Group, error) {
	resourcePath := BasePathGroups + "/" + id
	resp, err := c.makeAPIRequest(ctx, http.MethodGet, resourcePath, nil, nil)

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
	useHTTPPost bool,
	filter FilterExpression,
	cursor *string,
	count *int,
) (*GroupList, error) {
	resp, err := c.makeListRequest(ctx, useHTTPPost, BasePathGroups, filter, cursor, count)

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

func (c *Client) makeAPIRequest(
	ctx context.Context,
	method string,
	resourcePath string,
	queryString *string,
	body *io.Reader,
) (*http.Response, error) {
	var requestBody io.Reader
	if body != nil {
		requestBody = *body
	}

	req, err := http.NewRequestWithContext(ctx, method, c.scimHost+resourcePath, requestBody)
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

// makeListRequest creates a request to list SCIM resources (users or groups).
// It uses either GET or POST method based on the useHTTPPost parameter.
// It builds the request with the provided filter, cursor, and count parameters.
// For GET method, parameters are added to the query string.
// For POST method, parameters are included in the request body.
func (c *Client) makeListRequest(
	ctx context.Context,
	useHTTPPost bool,
	basePath string,
	filter FilterExpression,
	cursor *string,
	count *int,
) (*http.Response, error) {
	resourcePath := basePath + "/"
	method := http.MethodGet

	if useHTTPPost {
		resourcePath += PostSearchPath
		method = http.MethodPost
	}

	body, queryString, err := buildQueryStringAndBody(useHTTPPost, filter, cursor, count)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	return c.makeAPIRequest(ctx, method, resourcePath, queryString, body)
}
