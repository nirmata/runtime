package pushsink

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

// loadCredentials builds the sink's mutual TLS credentials. Every input is
// required: there is no path through this function that produces credentials
// which would fall back to plaintext or skip verification of the collector.
func loadCredentials(opts Options) (credentials.TransportCredentials, error) {
	for _, f := range []struct {
		flag string
		path string
	}{
		{"--push-tls-ca", opts.CAFile},
		{"--push-tls-cert", opts.CertFile},
		{"--push-tls-key", opts.KeyFile},
	} {
		if f.path == "" {
			return nil, fmt.Errorf("push sink: %s is required when --push-target is set", f.flag)
		}
	}

	cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("push sink: loading client certificate: %w", err)
	}

	pem, err := os.ReadFile(opts.CAFile)
	if err != nil {
		return nil, fmt.Errorf("push sink: reading collector CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("push sink: collector CA %s holds no certificate", opts.CAFile)
	}

	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		MinVersion:   tls.VersionTLS13,
	}), nil
}
