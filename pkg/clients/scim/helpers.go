package scim

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.tools.sap/kms/cmk/utils/ptr"
)

func setSCIMHeaders(req *http.Request) {
	if req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodPatch {
		req.Header.Set("Content-Type", ApplicationSCIMJson)
	}

	req.Header.Set("Accept", ApplicationSCIMJson)
}

func buildBodyFromParams(filter *FilterExpression, count *int, cursor *string) (io.Reader, error) {
	searchRequest := SearchRequest{
		Schemas: []string{SearchRequestSchema},
		Count:   count,
		Cursor:  cursor,
	}
	if filter != nil && (*filter != NullFilterExpression{}) {
		searchRequest.Filter = ptr.PointTo((*filter).ToString())
	}

	jsonBody, err := json.Marshal(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal search request: %w", err)
	}

	return bytes.NewReader(jsonBody), nil
}

func buildQueryStringFromParams(filter *FilterExpression, cursor *string, count *int) string {
	query := url.Values{}
	if cursor != nil {
		query.Add("cursor", *cursor)
	}

	if count != nil {
		query.Add("count", strconv.Itoa(*count))
	}

	if (filter != nil) && (*filter != NullFilterExpression{}) {
		query.Add("filter", (*filter).ToString())
	}

	return query.Encode()
}

func buildQueryStringAndBody(
	useHTTPPost bool,
	filter *FilterExpression,
	cursor *string,
	count *int,
) (*io.Reader, *string, error) {
	var (
		body        io.Reader
		queryString string
		err         error
	)

	if useHTTPPost {
		body, err = buildBodyFromParams(filter, count, cursor)
	} else {
		queryString = buildQueryStringFromParams(filter, cursor, count)
	}

	if err != nil {
		return nil, nil, err
	}

	return &body, &queryString, nil
}
