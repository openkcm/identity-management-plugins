package scim

import (
	"github.com/openkcm/identity-management-plugins/pkg/clients/scim"
	"github.com/openkcm/identity-management-plugins/pkg/config"
)

func (p *Plugin) SetTestClient(host string, groupFilterAttribute, userFilterAttribute *string) {
	p.scimClient = &scim.Client{
		Params: config.Params{},
	}
	p.config.Params = config.Params{
		Host:           host,
		GroupAttribute: groupFilterAttribute,
		UserAttribute:  userFilterAttribute,
	}
}
