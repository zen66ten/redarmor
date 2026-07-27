package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// selfSignedCert mints a cert with the given validity window, so tests can
// point Fetch at a server whose NotAfter is known in advance.
func selfSignedCert(t *testing.T, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
}

func TestFetch(t *testing.T) {
	wantNotAfter := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	cert := selfSignedCert(t, time.Now().Add(-24*time.Hour), wantNotAfter)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	defer server.Close()

	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host/port: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got, err := Fetch(ctx, host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if !got.NotAfter.Equal(wantNotAfter) {
		t.Errorf("NotAfter = %v, want %v", got.NotAfter, wantNotAfter)
	}
}

func TestFetch_DialFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Nothing listens here, so DialContext must fail and Fetch must
	// wrap that failure rather than panic or return a nil error.
	_, err := Fetch(ctx, "127.0.0.1", "1", time.Second)
	if err == nil {
		t.Fatal("expected error dialing closed port, got nil")
	}
}