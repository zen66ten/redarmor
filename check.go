package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

func Fetch(ctx context.Context, host string, port string, timeout time.Duration) (*x509.Certificate, error) {
	dialer := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			InsecureSkipVerify: true, //this is deliberately set to true to allow fetching certificates from servers with self-signed, expired or invalid certificates
			ServerName:         host,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", host, err)
	}
	defer conn.Close()

	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates found for %s", host)
	}
	return state.PeerCertificates[0], nil
}
