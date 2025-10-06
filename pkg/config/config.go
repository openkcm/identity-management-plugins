package config

import "github.com/openkcm/common-sdk/pkg/commoncfg"

type Params struct {
	GroupAttribute *string `yaml:"groupAttribute"`
	UserAttribute  *string `yaml:"userAttribute"`
}

type Config struct {
	Host   commoncfg.SourceRef `yaml:"host"`
	Auth   commoncfg.SecretRef `yaml:"auth"`
	Params Params              `yaml:"params"`
}
