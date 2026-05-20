package scim

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/stretchr/testify/assert"

	"github.com/openkcm/identity-management-plugins/pkg/clients/scim"
)

func getLogger() hclog.Logger {
	return hclog.New(&hclog.LoggerOptions{Level: hclog.Error})
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

	client, err := scim.NewClient(secretRef, getLogger())
	assert.NoError(t, err)

	p.scimClient = client
	p.params = Params{
		BaseHost:                host,
		GroupAttribute:          groupFilterAttribute,
		UserAttribute:           userFilterAttribute,
		AllowSearchUsersByGroup: true,
	}
}
