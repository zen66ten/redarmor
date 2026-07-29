package main

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	thresholds := Thresholds{WarningDays: 30, CriticalDays: 7}

	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		want      Status
	}{
		{
			name:      "ok, comfortably inside window",
			notBefore: now.Add(-24 * time.Hour),
			notAfter:  now.Add(100 * 24 * time.Hour),
			want:      StatusOK,
		},
		{
			name:      "warning, exactly WarningDays remaining",
			notBefore: now.Add(-24 * time.Hour),
			notAfter:  now.Add(30 * 24 * time.Hour),
			want:      StatusWarning,
		},
		{
			name:      "critical, exactly CriticalDays remaining",
			notBefore: now.Add(-24 * time.Hour),
			notAfter:  now.Add(7 * 24 * time.Hour),
			want:      StatusCritical,
		},
		{
			name:      "critical, truncation not rounding",
			notBefore: now.Add(-24 * time.Hour),
			// 7 days + 12 hours remaining truncates to 7 (Critical).
			// A rounding implementation would round this up to 8 and
			// misreport Warning instead.
			notAfter: now.Add(7*24*time.Hour + 12*time.Hour),
			want:     StatusCritical,
		},
		{
			name:      "expired",
			notBefore: now.Add(-100 * 24 * time.Hour),
			notAfter:  now.Add(-24 * time.Hour),
			want:      StatusExpired,
		},
		{
			name:      "not yet valid",
			notBefore: now.Add(10 * 24 * time.Hour),
			notAfter:  now.Add(100 * 24 * time.Hour),
			want:      StatusNotYetValid,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert := &x509.Certificate{NotBefore: tc.notBefore, NotAfter: tc.notAfter}
			got := Classify(cert, now, thresholds)
			if got != tc.want {
				t.Errorf("Classify() = %v, want %v", got, tc.want)
			}
		})
	}
}