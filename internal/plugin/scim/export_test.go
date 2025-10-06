package scim

import (
	"log/slog"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/magodo/slog2hclog"
	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/stretchr/testify/assert"

	"github.com/openkcm/identity-management-plugins/pkg/clients/scim"
)

func getLogger() hclog.Logger {
	logLevelPlugin := new(slog.LevelVar)
	logLevelPlugin.Set(slog.LevelError)

	return slog2hclog.New(slog.Default(), logLevelPlugin)
}

func (p *Plugin) SetTestClient(t *testing.T, host string, groupFilterAttribute, userFilterAttribute string) {
	t.Helper()

	secretRef := commoncfg.SecretRef{
		Type: commoncfg.BasicSecretType,
		Basic: commoncfg.BasicAuth{
			Username: commoncfg.SourceRef{
				Source: commoncfg.EmbeddedSourceValue,
				Value:  "",
			},
			Password: commoncfg.SourceRef{
				Source: commoncfg.EmbeddedSourceValue,
				Value:  "",
			},
		},
	}

	hostRef := commoncfg.SourceRef{
		Source: commoncfg.EmbeddedSourceValue,
		Value:  host,
	}

	client, err := scim.NewClient(hostRef, secretRef, getLogger())
	assert.NoError(t, err)

	p.scimClient = client
	p.params = Params{
		GroupAttribute:          groupFilterAttribute,
		UserAttribute:           userFilterAttribute,
		AllowSearchUsersByGroup: true,
	}
}
