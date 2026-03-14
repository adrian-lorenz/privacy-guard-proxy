package proxy

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

var (
	metricRequests    atomic.Uint64
	metricPIIFindings atomic.Uint64
	metricMaskedBytes atomic.Uint64

	metricTypeMu sync.Mutex
	metricByType = map[string]uint64{}
)

// RecordMetrics adds proxy processing metrics for one request.
func RecordMetrics(summary ScanSummary) {
	metricRequests.Add(1)
	if summary.PIIFound > 0 {
		metricPIIFindings.Add(uint64(summary.PIIFound))
	}
	if summary.MaskedBytes > 0 {
		metricMaskedBytes.Add(uint64(summary.MaskedBytes))
	}
	if len(summary.PIITypes) == 0 {
		return
	}
	metricTypeMu.Lock()
	for _, t := range summary.PIITypes {
		metricByType[t]++
	}
	metricTypeMu.Unlock()
}

// MetricsText returns a Prometheus-style text exposition.
func MetricsText() string {
	var sb strings.Builder
	sb.WriteString("# TYPE privacy_guard_requests_total counter\n")
	sb.WriteString(fmt.Sprintf("privacy_guard_requests_total %d\n", metricRequests.Load()))
	sb.WriteString("# TYPE privacy_guard_pii_findings_total counter\n")
	sb.WriteString(fmt.Sprintf("privacy_guard_pii_findings_total %d\n", metricPIIFindings.Load()))
	sb.WriteString("# TYPE privacy_guard_masked_bytes_total counter\n")
	sb.WriteString(fmt.Sprintf("privacy_guard_masked_bytes_total %d\n", metricMaskedBytes.Load()))

	metricTypeMu.Lock()
	types := make([]string, 0, len(metricByType))
	for t := range metricByType {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		sb.WriteString(fmt.Sprintf("privacy_guard_pii_type_total{type=%q} %d\n", t, metricByType[t]))
	}
	metricTypeMu.Unlock()
	return sb.String()
}
