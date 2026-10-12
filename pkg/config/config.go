package config

import "github.com/openkcm/common-sdk/pkg/commoncfg"

type Params struct {
	GroupAttribute        commoncfg.SourceRef `yaml:"groupAttribute"`
	UserAttribute         commoncfg.SourceRef `yaml:"userAttribute"`
	GroupMembersAttribute commoncfg.SourceRef `yaml:"groupMembersAttribute"`
	ListMethod            commoncfg.SourceRef `yaml:"listMethod"`
}

type Config struct {
	Host        commoncfg.SourceRef `yaml:"host"`
	Auth        commoncfg.SecretRef `yaml:"auth"`
	AuthContext commoncfg.SourceRef `yaml:"authContext"`
	Params      Params              `yaml:"params"`
}

type AuthContextConfig struct {
	HostField    string            `yaml:"hostField"`
	HeaderFields map[string]string `yaml:"headerFields"`
	BasePath     string            `yaml:"basePath"`
}

// StaticConfig configures the static SCIM plugin, which serves users and
// groups from JSON given in the plugin configuration instead of querying a
// SCIM server.
type StaticConfig struct {
	// JSONData is a JSON string with the users and groups to serve, using the
	// SCIM User and Group representations. Membership may be declared on the
	// group (members), on the user (groups), or both. Example:
	//
	//	json_data: |
	//	  {
	//	    "users":  [{"id": "u1", "userName": "alice", "emails": [{"value": "alice@example.com", "primary": true}]}],
	//	    "groups": [{"id": "g1", "displayName": "KeyAdmin", "members": [{"value": "u1"}]}]
	//	  }
	JSONData string `yaml:"json_data"`
}
