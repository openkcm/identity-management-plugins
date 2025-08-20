package scim

import (
	"github.com/openkcm/identity-management-plugins/pkg/clients/scim"
)

func (p *Plugin) SetTestClient(host string, groupFilterAttribute, userFilterAttribute *string) {
	p.scimClient = &scim.Client{
		Params: scim.Common{
			Host: host,
		},
	}
	p.requestParams = RequestParams{
		GroupAttribute: groupFilterAttribute,
		UserAttribute:  userFilterAttribute,
	}
}
