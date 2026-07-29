package main

import (
	"os"
	"testing"
	"time"
)

// TestWriteTable_Demo is a throwaway visual check, not an assertion-based
// test. Run with `go test -v -run TestWriteTable_Demo` to eyeball the
// rendered table before deciding on golden-file tests.
func TestWriteTable_Demo(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	results := []Result{
		{Host: "ok.example.com", Port: "443", Status: StatusOK, DaysLeft: 84, NotAfter: now.Add(84 * 24 * time.Hour), Issuer: "R3"},
		{Host: "warn.example.com", Port: "443", Status: StatusWarning, DaysLeft: 20, NotAfter: now.Add(20 * 24 * time.Hour), Issuer: "R3"},
		{Host: "critical.example.com", Port: "8443", Status: StatusCritical, DaysLeft: 3, NotAfter: now.Add(3 * 24 * time.Hour), Issuer: "DigiCert"},
		{Host: "expired.example.com", Port: "443", Status: StatusExpired, DaysLeft: -10, NotAfter: now.Add(-10 * 24 * time.Hour), Issuer: "DigiCert"},
		{Host: "future.example.com", Port: "443", Status: StatusNotYetValid, DaysLeft: 40, NotAfter: now.Add(40 * 24 * time.Hour), Issuer: "R3"},
		{Host: "unreachable.example.com", Port: "443", Err: &testErr{"dial tcp: connection refused"}},
		{Host: "aaa-first-alphabetically.example.com", Port: "443", Err: &testErr{"dial tcp: i/o timeout"}},
	}

	if err := WriteTable(os.Stdout, results); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}

	os.Stdout.WriteString("\n--- JSON ---\n")

	if err := WriteJSON(os.Stdout, results); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
}

type testErr struct{ msg string }

func (e *testErr) Error() string { return e.msg }