package main

import (
	"crypto/x509"
	"encoding/json"
	"time"
)

type Status int

const (
	StatusUnknown Status = iota // zero value: never classified, e.g. a failed fetch
	StatusOK
	StatusWarning
	StatusNotYetValid
	StatusExpired
	StatusCritical
)

func (s Status) String() string {

	switch s {
	case StatusOK:
		return "ok"
	case StatusWarning:
		return "warning"
	case StatusNotYetValid:
		return "not yet valid"
	case StatusExpired:
		return "expired"
	case StatusCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// MarshalJSON serializes Status as its String() name, so JSON output is
// legible without needing the source to decode the integer.
func (s Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

type Result struct {
	Host     string
	Port     string
	NotAfter time.Time
	DaysLeft int
	Issuer   string
	Serial   string
	Status   Status
	Err      error
}

type Thresholds struct {
	WarningDays  int
	CriticalDays int
}

func Classify(cert *x509.Certificate, now time.Time, t Thresholds) Status {
	if now.Before(cert.NotBefore) {
		return StatusNotYetValid
	}
	if now.After(cert.NotAfter) {
		return StatusExpired
	}
	daysRemaining := int(cert.NotAfter.Sub(now) / (24 * time.Hour))
	if daysRemaining <= t.CriticalDays {
		return StatusCritical
	}
	if daysRemaining <= t.WarningDays {
		return StatusWarning
	}
	return StatusOK
}
