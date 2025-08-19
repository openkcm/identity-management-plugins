package scim

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.tools.sap/kms/cmk/internal/errs"
	"github.tools.sap/kms/cmk/utils/httpclient"
)

const (
	ApplicationSCIMJson = "application/scim+json"

	SearchRequestSchema = "urn:ietf:params:scim:api:messages:2.0:SearchRequest"

	BasePathGroups = "/Groups"
	BasePathUsers  = "/Users"
	PostSearchPath = ".search"
)

var (
	ErrGetUser         = errors.New("error getting SCIM user")
	ErrListUsers       = errors.New("error listing SCIM users")
	ErrGetGroup        = errors.New("error getting SCIM group")
	ErrListGroups      = errors.New("error listing SCIM groups")
	ErrClientIDMissing = errors.New("client ID is required")
	ErrAuthParams      = errors.New("must provide client secret or TLS config")
)

// APIParams contains the parameters needed to create a new API client
// supporting client authentication via client secret or mTLS.
type APIParams struct {
	Host         string
	ClientID     string
	ClientSecret string
	TLSConfig    *tls.Config
}

type APIClient struct {
	httpClient http.Client
	Params     APIParams
}

func NewClient(params APIParams) (*APIClient, error) {
	if params.ClientID == "" {
		return nil, ErrClientIDMissing
	}

	if params.TLSConfig == nil && params.ClientSecret == "" {
		// If TLSConfig is not provided, client secret must be provided
		return nil, ErrAuthParams
	}

	return &APIClient{
		httpClient: http.Client{
			Transport: &http.Transport{
				TLSClientConfig: params.TLSConfig,
			},
		},
		Params: params,
	}, nil
}

// GetUser retrieves a SCIM user by its ID.
func (c *APIClient) GetUser(ctx context.Context, id string) (*User, error) {
	resourcePath := BasePathUsers + "/" + id
	resp, err := c.makeAPIRequest(ctx, http.MethodGet, resourcePath, nil, nil)

	if resp != nil {
		defer func() {
			err := resp.Body.Close()
			if err != nil {
				slog.ErrorContext(ctx, "failed to close GetUser response body", "error", err)
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
func (c *APIClient) ListUsers(
	ctx context.Context,
	useHTTPPost bool,
	filter *FilterExpression,
	cursor *string,
	count *int,
) (*UserList, error) {
	resp, err := c.makeListRequest(ctx, useHTTPPost, BasePathUsers, filter, cursor, count)
	if resp != nil {
		defer func() {
			err := resp.Body.Close()
			if err != nil {
				slog.ErrorContext(ctx, "failed to close ListUsers response body", "error", err)
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
func (c *APIClient) GetGroup(ctx context.Context, id string) (*Group, error) {
	resourcePath := BasePathGroups + "/" + id
	resp, err := c.makeAPIRequest(ctx, http.MethodGet, resourcePath, nil, nil)

	if resp != nil {
		defer func() {
			err := resp.Body.Close()
			if err != nil {
				slog.ErrorContext(ctx, "failed to close GetGroup response body", "error", err)
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
func (c *APIClient) ListGroups(
	ctx context.Context,
	useHTTPPost bool,
	filter *FilterExpression,
	cursor *string,
	count *int,
) (*GroupList, error) {
	resp, err := c.makeListRequest(ctx, useHTTPPost, BasePathGroups, filter, cursor, count)

	if resp != nil {
		defer func() {
			err := resp.Body.Close()
			if err != nil {
				slog.ErrorContext(ctx, "failed to close ListGroups response body", "error", err)
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

func (c *APIClient) setAuth(req *http.Request) {
	if c.Params.ClientSecret != "" {
		req.SetBasicAuth(c.Params.ClientID, c.Params.ClientSecret)
	} else {
		// For client certificate auth, we only need to add the client_id to the query string
		query := req.URL.Query()
		query.Add("client_id", c.Params.ClientID)
		req.URL.RawQuery = query.Encode()
	}
}

func (c *APIClient) makeAPIRequest(
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

	req, err := http.NewRequestWithContext(ctx, method, c.Params.Host+resourcePath, requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	setSCIMHeaders(req)

	if queryString != nil {
		req.URL.RawQuery = *queryString
	}

	c.setAuth(req)

	resp, err := c.httpClient.Do(req)
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
func (c *APIClient) makeListRequest(
	ctx context.Context,
	useHTTPPost bool,
	basePath string,
	filter *FilterExpression,
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
