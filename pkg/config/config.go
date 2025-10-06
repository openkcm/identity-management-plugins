package config

import "github.com/openkcm/common-sdk/pkg/commoncfg"

type Params struct {
	GroupAttribute          commoncfg.SourceRef `yaml:"groupAttribute"`
	UserAttribute           commoncfg.SourceRef `yaml:"userAttribute"`
	GroupMembersAttribute   commoncfg.SourceRef `yaml:"groupMembersAttribute"`
	ListMethod              commoncfg.SourceRef `yaml:"listMethod"`
	AllowSearchUsersByGroup commoncfg.SourceRef `yaml:"allowSearchUsersByGroup"`
}

type Config struct {
	Host   commoncfg.SourceRef `yaml:"host"`
	Auth   commoncfg.SecretRef `yaml:"auth"`
	Params Params              `yaml:"params"`
}
