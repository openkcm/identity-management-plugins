package scim

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/identity-management-plugins/pkg/config"
	errs "github.com/openkcm/identity-management-plugins/pkg/utils/errs"
	"github.com/openkcm/identity-management-plugins/pkg/utils/httpclient"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	ApplicationSCIMJson = "application/scim+json"

	SearchRequestSchema = "urn:ietf:params:scim:api:messages:2.0:SearchRequest"

	BasePathGroups = "/Groups"
	BasePathUsers  = "/Users"
	PostSearchPath = ".search"
	GET_TOKEN_PATH = "/oauth/token"
)

var (
	ErrGetUser         = errors.New("error getting SCIM user")
	ErrListUsers       = errors.New("error listing SCIM users")
	ErrGetGroup        = errors.New("error getting SCIM group")
	ErrListGroups      = errors.New("error listing SCIM groups")
	ErrClientIDMissing = errors.New("client ID is required")
	ErrAuthParams      = errors.New("must provide client secret or TLS config")
)

type Client struct {
	httpClient *http.Client

	scimHost string
}

func NewClientFromAPI(ctx context.Context, cfg *config.Config) (*Client, error) {
	httpClient, err := createHTTPClient(ctx, cfg.Auth)
	if err != nil {
		return nil, err
	}

	return &Client{
		httpClient: httpClient,
		scimHost:   cfg.Host,
	}, nil
}

// GetUser retrieves a SCIM user by its ID.
func (c *Client) GetUser(ctx context.Context, id string) (*User, error) {
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
func (c *Client) GetGroup(ctx context.Context, id string) (*Group, error) {
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

	setSCIMHeaders(req)

	if queryString != nil {
		req.URL.RawQuery = *queryString
	}

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

func initClientCredsConfig(clientId, grantType string) *clientcredentials.Config {
	clientConfig := &clientcredentials.Config{
		ClientID:  clientId,
		AuthStyle: oauth2.AuthStyleInParams,
	}
	clientConfig.EndpointParams = url.Values{
		"grant_type": {grantType},
	}

	return clientConfig
}

func createHTTPClient(ctx context.Context, oauth2 commoncfg.OAuth2) (*http.Client, error) {
	clientId, err := commoncfg.LoadValueFromSourceRef(oauth2.ClientID)
	if err != nil {
		return nil, errors.New("failed to load client id")
	}
	url, err := commoncfg.LoadValueFromSourceRef(oauth2.URL)
	if err != nil {
		return nil, errors.New("failed to load the oauth2 url")
	}

	if oauth2.MTLS != nil {
		return getX509Client(ctx, string(url), string(clientId), oauth2.MTLS)
	}

	if oauth2.ClientSecret != nil {
		clientSecret, err := commoncfg.LoadValueFromSourceRef(*oauth2.ClientSecret)
		if err != nil {
			return nil, errors.New("failed to load client secret")
		}

		clientConfig := initClientCredsConfig(string(clientId), "client_credentials")
		clientConfig.ClientSecret = string(clientSecret)
		clientConfig.TokenURL = string(url) + GET_TOKEN_PATH

		return clientConfig.Client(ctx), nil
	}

	return nil, errors.New("failed to create the http client")
}

func getX509Client(ctx context.Context, url, clientId string, mtls *commoncfg.MTLS) (*http.Client, error) {
	clientConfig := initClientCredsConfig(clientId, "client_x509")
	clientConfig.TokenURL = url + GET_TOKEN_PATH

	cert, err := commoncfg.LoadMTLSClientCertificate(*mtls)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client certificate x509 pair")
	}

	tokenBaseClient := &http.Client{
		Transport: &http.Transport{ // client cert auth
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{*cert},
			},
		},
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, tokenBaseClient)
	return clientConfig.Client(ctx), nil
}
