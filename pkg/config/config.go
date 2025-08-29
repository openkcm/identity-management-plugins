package config

import "github.com/openkcm/common-sdk/pkg/commoncfg"

type Params struct {
	GroupAttribute *string `yaml:"groupAttribute"`
	UserAttribute  *string `yaml:"userAttribute"`
}

type Config struct {
	Host   string `yaml:"host"`
	Params Params `yaml:"params"`

	Auth commoncfg.SecretRef `yaml:"auth"`
}
