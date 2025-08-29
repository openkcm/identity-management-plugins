package scim

import (
	"log/slog"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/magodo/slog2hclog"
	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/stretchr/testify/assert"

	"github.com/openkcm/identity-management-plugins/pkg/clients/scim"
	"github.com/openkcm/identity-management-plugins/pkg/config"
)

func getLogger() hclog.Logger {
	logLevelPlugin := new(slog.LevelVar)
	logLevelPlugin.Set(slog.LevelError)

	return slog2hclog.New(slog.Default(), logLevelPlugin)
}

func (p *Plugin) SetTestClient(t *testing.T, host string, groupFilterAttribute, userFilterAttribute *string) {
	t.Helper()

	config := &config.Config{
		Host: host,
		Auth: commoncfg.SecretRef{
			Type: commoncfg.BasicSecretType,
			Basic: commoncfg.BasicAuth{
				Username: commoncfg.SourceRef{
					Source: commoncfg.EmbeddedSourceValue,
					Value:  ""},
				Password: commoncfg.SourceRef{
					Source: commoncfg.EmbeddedSourceValue,
					Value:  ""},
			},
		},
		Params: config.Params{
			GroupAttribute: groupFilterAttribute,
			UserAttribute:  userFilterAttribute,
		},
	}
	client, err := scim.NewClient(config, getLogger())
	assert.NoError(t, err)

	p.scimClient = client
	p.config = config
}
