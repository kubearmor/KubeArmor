// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package config

import (
	"flag"

	"github.com/spf13/viper"
)

type RelayConfig struct {
	GRPC            string
	LivenessPort    string
	TLSEnabled      bool
	TLSCertPath     string
	TLSCertProvider string
}

var GlobalConfig RelayConfig

const (
	ConfigGRPC            string = "gRPCPort"
	ConfigLivenessPort    string = "livenessPort"
	ConfigTLSEnabled      string = "tlsEnabled"
	ConfigTLSCertPath     string = "tlsCertPath"
	ConfigTLSCertProvider string = "tlsCertProvider"
	SelfCertProvider      string = "self"
	ExternalCertProvider  string = "external"
)

func readCmdLineParams() {
	grpcStr := flag.String(ConfigGRPC, "32767", "gRPC port")
	livenessPort := flag.String(ConfigLivenessPort, "32766", "liveness probe port")
	tlsEnabled := flag.Bool(ConfigTLSEnabled, false, "enable tls to connect with kubearmor ssl service")
	tlsCertPath := flag.String(ConfigTLSCertPath, "/var/lib/kubearmor/tls", "path to tls certs files ca.crt, client.crt, client.key")
	tlsCertProvider := flag.String(ConfigTLSCertProvider, ExternalCertProvider, "source of certificate {self|external}, self: create certificate dynamically, external: provided by some external entity")
	flag.Parse()
	viper.SetDefault(ConfigGRPC, grpcStr)
	viper.SetDefault(ConfigLivenessPort, livenessPort)
	viper.SetDefault(ConfigTLSEnabled, tlsEnabled)
	viper.SetDefault(ConfigTLSCertPath, tlsCertPath)
	viper.SetDefault(ConfigTLSCertProvider, tlsCertProvider)
}

func LoadConfig() error {

	readCmdLineParams()

	GlobalConfig.GRPC = viper.GetString(ConfigGRPC)
	GlobalConfig.LivenessPort = viper.GetString(ConfigLivenessPort)
	GlobalConfig.TLSEnabled = viper.GetBool(ConfigTLSEnabled)
	GlobalConfig.TLSCertPath = viper.GetString(ConfigTLSCertPath)
	GlobalConfig.TLSCertProvider = viper.GetString(ConfigTLSCertProvider)
	return nil
}
