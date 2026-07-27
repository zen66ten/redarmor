package main

type Status int

const (
	StatusOK Status = iota
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
