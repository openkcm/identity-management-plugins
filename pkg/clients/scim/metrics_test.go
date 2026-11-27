package scim_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/openkcm/identity-management-plugins/pkg/clients/scim"
)

func TestSCIMCallEmitsOTELMetrics(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	prev := otel.GetMeterProvider()

	otel.SetMeterProvider(provider)

	t.Cleanup(func() { otel.SetMeterProvider(prev) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := fastRetryClient(t)

	_, err := client.GetUser(t.Context(), "123", scim.RequestParams{Host: server.URL})
	require.Error(t, err)

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &rm))
	require.NotEmpty(t, rm.ScopeMetrics)

	metrics := rm.ScopeMetrics[0].Metrics

	latency := findMetric(metrics, "http.client.request.duration")
	require.NotNil(t, latency)
	hist, ok := latency.Data.(metricdata.Histogram[float64])
	require.True(t, ok)
	require.NotEmpty(t, hist.DataPoints)
	assert.Positive(t, hist.DataPoints[0].Count)

	errs := findMetric(metrics, "http.client.request.errors")
	require.NotNil(t, errs)
	sum, ok := errs.Data.(metricdata.Sum[int64])
	require.True(t, ok)

	var total int64
	for _, dp := range sum.DataPoints {
		total += dp.Value
	}

	assert.Positive(t, total)
}

func findMetric(metrics []metricdata.Metrics, name string) *metricdata.Metrics {
	for i := range metrics {
		if metrics[i].Name == name {
			return &metrics[i]
		}
	}

	return nil
}
