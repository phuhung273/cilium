// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"context"
	"crypto/tls"
	"log/slog"
	"regexp"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	k8sCtrlMetrics "sigs.k8s.io/controller-runtime/pkg/certwatcher/metrics"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

// goCustomCollectorsRX tracks enabled go runtime metrics.
var goCustomCollectorsRX = regexp.MustCompile(`^/sched/latencies:seconds`)

type params struct {
	cell.In

	Logger     *slog.Logger
	Lifecycle  cell.Lifecycle
	Shutdowner hive.Shutdowner
	JobGroup   job.Group

	Cfg       Config
	SharedCfg SharedConfig

	Metrics []metric.WithMetadata `group:"hive-metrics"`

	Registry                   *metrics.Registry
	PrometheusTlsConfigPromise prometheusTLSConfigPromise
}

// Note: metrics are always initialized so we have access to sampler ring buffer data
// for debugging. However, actual prometheus server will be started depending on if
// metrics are enabled.
func initializeMetrics(p params) {
	p.Registry.MustRegister(collectors.NewGoCollector(
		collectors.WithGoCollectorRuntimeMetrics(
			collectors.GoRuntimeMetricsRule{Matcher: goCustomCollectorsRX},
		),
	))

	p.Registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{Namespace: metrics.CiliumOperatorNamespace}))

	for _, metric := range p.Metrics {
		p.Registry.MustRegister(metric.(prometheus.Collector))
	}

	metrics.NewLegacyMetrics()
	p.Registry.MustRegister(
		metrics.VersionMetric,
		metrics.KVStoreOperationsDuration,
		metrics.KVStoreEventsQueueDuration,
		metrics.KVStoreQuorumErrors,
		metrics.APILimiterProcessingDuration,
		metrics.APILimiterWaitDuration,
		metrics.APILimiterRequestsInFlight,
		metrics.APILimiterRateLimit,
		metrics.APILimiterProcessedRequests,

		metrics.WorkQueueDepth,
		metrics.WorkQueueAddsTotal,
		metrics.WorkQueueLatency,
		metrics.WorkQueueDuration,
		metrics.WorkQueueUnfinishedWork,
		metrics.WorkQueueLongestRunningProcessor,
		metrics.WorkQueueRetries,
	)

	p.Registry.Register(k8sCtrlMetrics.ReadCertificateTotal)
	p.Registry.Register(k8sCtrlMetrics.ReadCertificateErrors)

	metrics.InitOperatorMetrics()
	p.Registry.MustRegister(metrics.ErrorsWarnings)
	metrics.FlushLoggingMetrics()

	// Initialize Prometheus server with default config
	p.Registry.InitalizeServer()

	p.JobGroup.Add(job.OneShot("operator-prometheus-server", func(ctx context.Context, _ cell.Health) error {
		tlsEnabled := p.PrometheusTlsConfigPromise != nil
		if tlsEnabled {
			p.Logger.Info("Waiting for TLS certificates to become available")
			certLoaderWatchedServerConfig, err := p.PrometheusTlsConfigPromise.Await(ctx)
			if err != nil {
				return err
			}

			// Config Prometheus server to run with TLS
			p.Registry.ConfigureServerTLS(certLoaderWatchedServerConfig.ServerConfig(&tls.Config{
				MinVersion: tls.VersionTLS13,
			}))
		}
		go p.Registry.StartServer()
		return nil
	}))

	p.Lifecycle.Append(cell.Hook{
		OnStop: func(hc cell.HookContext) error {
			return p.Registry.StopServer(hc)
		},
	})
}
