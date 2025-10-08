// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/promise"
)

type tlsConfigPromise promise.Promise[*certloader.WatchedServerConfig]

// CertloaderGroup provides a promise that can be used to obtain a TLS config
// capable of automatically sourcing/reloading certificates from disk.
//
// We wrap the promise in our own type to avoid conflicts/replacements with other
// certloader promises. We use a group instead of a module to be able to use
// cell.ProvidePrivate and avoid providing the promise to the rest of the hive.
var CertloaderGroup = cell.Group(
	cell.ProvidePrivate(func(lc cell.Lifecycle, jobGroup job.Group, log *slog.Logger, cfg certloaderConfig) (tlsConfigPromise, error) {
		config := certloader.Config{
			TLS:              cfg.EnableServerTLS,
			TLSCertFile:      cfg.TLSCertFile,
			TLSKeyFile:       cfg.TLSKeyFile,
			TLSClientCAFiles: cfg.TLSClientCAFiles,
		}
		return certloader.NewWatchedServerConfigPromise(lc, jobGroup, log, config)
	}),
	cell.Config(defaultCertloaderConfig),
)

type certloaderConfig struct {
	EnableServerTLS  bool     `mapstructure:"prometheus-enable-tls"`
	TLSCertFile      string   `mapstructure:"prometheus-tls-cert-file"`
	TLSKeyFile       string   `mapstructure:"prometheus-tls-key-file"`
	TLSClientCAFiles []string `mapstructure:"prometheus-tls-client-ca-files"`
}

var defaultCertloaderConfig = certloaderConfig{
	EnableServerTLS:  false,
	TLSCertFile:      "",
	TLSKeyFile:       "",
	TLSClientCAFiles: []string{},
}

func (def certloaderConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("prometheus-enable-tls", def.EnableServerTLS, "Allow Prometheus server to run on the given listen address without TLS.")
	flags.String("prometheus-tls-cert-file", def.TLSCertFile, "Path to the public key file for the Prometheus server. The file must contain PEM encoded data.")
	flags.String("prometheus-tls-key-file", def.TLSKeyFile, "Path to the private key file for the Prometheus server. The file must contain PEM encoded data.")
	flags.StringSlice("prometheus-tls-client-ca-files", def.TLSClientCAFiles, "Paths to one or more public key files of client CA certificates to use for TLS with mutual authentication (mTLS). The files must contain PEM encoded data. When provided, this option effectively enables mTLS.")
}
