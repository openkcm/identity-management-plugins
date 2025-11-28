package main

import (
	"log/slog"

	"github.com/openkcm/common-sdk/pkg/utils"
	"github.com/openkcm/plugin-sdk/pkg/plugin"

	idmangv1 "github.com/openkcm/plugin-sdk/proto/plugin/identity_management/v1"
	configv1 "github.com/openkcm/plugin-sdk/proto/service/common/config/v1"

	"github.com/openkcm/identity-management-plugins/internal/plugin/scim"
)

var BuildInfo = "{}"

func main() {
	value, err := utils.ExtractFromComplexValue(BuildInfo)
	if err != nil {
		slog.Warn("Failed to extract BuildInfo")
	}

	p := scim.NewPlugin(value)

	plugin.Serve(
		idmangv1.IdentityManagementServicePluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}
