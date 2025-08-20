package main

import (
	"github.com/openkcm/plugin-sdk/pkg/plugin"

	idmangv1 "github.com/openkcm/plugin-sdk/proto/plugin/identity_management/v1"
	configv1 "github.com/openkcm/plugin-sdk/proto/service/common/config/v1"

	"github.com/openkcm/identity-management-plugins/internal/plugin/scim"
)

func main() {
	p := scim.NewPlugin()

	plugin.Serve(
		idmangv1.IdentityManagementServicePluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}
