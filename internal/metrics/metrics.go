// Package metrics records HTTP, storage and authentication metrics and serves them in the Prometheus text format.
package metrics

import (
	"context"
	"io"
	"math"
	"net/http"
	"strconv"

	"github.com/felixge/httpsnoop"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
)

// namespace prefixes the name of every metric the server defines, and routeLabel names the route pattern label.
const (
	namespace  = "anchor_lfs"
	routeLabel = "route"
)

// durationBuckets are the request duration histogram bounds in seconds, from quick API calls to long transfers.
var durationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300}

// Metrics holds the server's collectors and the registry that serves them.
type Metrics struct {
	registry      *prometheus.Registry
	requests      *prometheus.CounterVec
	duration      *prometheus.HistogramVec
	requestBytes  *prometheus.CounterVec
	responseBytes *prometheus.CounterVec
}

// New returns Metrics with the HTTP, build information, Go runtime and process collectors registered.
func New(version, commit string) *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "http_requests_total",
			Help:      "HTTP requests handled, by route pattern and status code.",
		}, []string{routeLabel, "code"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "http_request_duration_seconds",
			Help:      "Time taken to handle HTTP requests, by route pattern.",
			Buckets:   durationBuckets,
		}, []string{routeLabel}),
		requestBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "http_request_body_bytes_total",
			Help:      "Request body bytes read, by route pattern.",
		}, []string{routeLabel}),
		responseBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "http_response_body_bytes_total",
			Help:      "Response body bytes written, by route pattern.",
		}, []string{routeLabel}),
	}
	buildInfo := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace:   namespace,
		Name:        "build_info",
		Help:        "Always 1, labelled with the running version and commit.",
		ConstLabels: prometheus.Labels{"version": version, "commit": commit},
	}, func() float64 { return 1 })
	m.registry.MustRegister(m.requests, m.duration, m.requestBytes, m.responseBytes, buildInfo,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// Instrument records the route pattern, status code, duration and body sizes of each request that mux handles.
func (m *Metrics) Instrument(mux http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := &countingReader{ReadCloser: r.Body}
		r.Body = body
		captured := httpsnoop.CaptureMetrics(mux, w, r)

		route := r.Pattern
		m.requests.WithLabelValues(route, strconv.Itoa(captured.Code)).Inc()
		m.duration.WithLabelValues(route).Observe(captured.Duration.Seconds())
		m.requestBytes.WithLabelValues(route).Add(float64(body.n))
		m.responseBytes.WithLabelValues(route).Add(float64(captured.Written))
	})
}

// countingReader counts the bytes read through it.
type countingReader struct {
	io.ReadCloser
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.n += int64(n)
	return n, err
}

// RegisterAvailableSpace adds a gauge of the bytes free in local storage, read from available at each scrape.
func (m *Metrics) RegisterAvailableSpace(available func(context.Context) (uint64, error)) {
	m.registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "storage_available_bytes",
		Help:      "Bytes free on the filesystem that holds local storage.",
	}, func() float64 {
		free, err := available(context.Background())
		if err != nil {
			log.Warn().Err(err).Msg("reading free space for metrics")
			return math.NaN()
		}
		return float64(free)
	}))
}

// RegisterAuthCache adds counters of authentication cache hits and misses, read from stats at each scrape.
func (m *Metrics) RegisterAuthCache(stats func() (hits, misses uint64)) {
	m.registry.MustRegister(&authCacheCollector{
		desc: prometheus.NewDesc(namespace+"_auth_cache_requests_total",
			"GitHub authentications answered from the cache (hit) or by asking GitHub (miss).", []string{"result"}, nil),
		stats: stats,
	})
}

// authCacheCollector reports the hit and miss counts that stats returns.
type authCacheCollector struct {
	desc  *prometheus.Desc
	stats func() (hits, misses uint64)
}

func (c *authCacheCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

func (c *authCacheCollector) Collect(ch chan<- prometheus.Metric) {
	hits, misses := c.stats()
	ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, float64(hits), "hit")
	ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, float64(misses), "miss")
}

// Handler serves the registered metrics in the Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}
