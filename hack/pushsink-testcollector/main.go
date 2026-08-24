package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/nirmata/runtime/pkg/proto/finding"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	listen := flag.String("listen", ":9444", "address to listen on")
	tlsCert := flag.String("tls-cert", "", "server certificate (PEM)")
	tlsKey := flag.String("tls-key", "", "server private key (PEM)")
	tlsClientCA := flag.String("tls-client-ca", "", "PEM bundle of accepted client CAs; requires --tls-cert and --tls-key, enables mTLS")
	refuseAfter := flag.Uint64("refuse-after", 0, "refuse every finding once this many have been received in total across the process lifetime (0 = never)")
	delay := flag.Duration("delay", 0, "sleep this long before each Recv, to simulate a slow collector")
	flag.Parse()

	creds, mode, err := serverCredentials(*tlsCert, *tlsKey, *tlsClientCA)
	if err != nil {
		log.Fatalf("pushsink-testcollector: %v", err)
	}

	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("pushsink-testcollector: listening on %s: %v", *listen, err)
	}

	var opts []grpc.ServerOption
	if creds != nil {
		opts = append(opts, grpc.Creds(creds))
	}
	srv := grpc.NewServer(opts...)
	finding.RegisterFindingServiceServer(srv, &collector{refuseAfter: *refuseAfter, delay: *delay})

	log.Printf("pushsink-testcollector: listening on %s (%s)", *listen, mode)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("pushsink-testcollector: %v", err)
	}
}

// serverCredentials builds the collector's server-side TLS configuration.
// With no TLS flags set it returns nil credentials for a plaintext listener;
// otherwise it returns credentials matching the push sink's mandatory TLS
// 1.3 minimum, requiring a verified client certificate when clientCAFile is
// set. mode reports "plaintext", "TLS", or "mTLS" for the startup log line.
func serverCredentials(certFile, keyFile, clientCAFile string) (creds credentials.TransportCredentials, mode string, err error) {
	if certFile == "" && keyFile == "" {
		if clientCAFile != "" {
			return nil, "", errors.New("--tls-client-ca requires --tls-cert and --tls-key")
		}
		return nil, "plaintext", nil
	}
	if certFile == "" || keyFile == "" {
		return nil, "", errors.New("--tls-cert and --tls-key must both be set, or neither")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, "", fmt.Errorf("loading server certificate: %w", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	mode = "TLS"
	if clientCAFile != "" {
		pem, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, "", fmt.Errorf("reading client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, "", fmt.Errorf("client CA %s holds no certificate", clientCAFile)
		}
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = pool
		mode = "mTLS"
	}

	return credentials.NewTLS(cfg), mode, nil
}

type collector struct {
	finding.UnimplementedFindingServiceServer
	refuseAfter uint64
	delay       time.Duration
	received    atomic.Uint64
}

func (c *collector) Report(st grpc.ClientStreamingServer[finding.Finding, finding.Ack]) error {
	if c.refuseAfter > 0 && c.received.Load() >= c.refuseAfter {
		return status.Error(codes.Unavailable, "refusing findings (--refuse-after reached)")
	}

	var streamCount uint64
	for {
		if c.delay > 0 {
			time.Sleep(c.delay)
		}

		msg, err := st.Recv()
		if errors.Is(err, io.EOF) {
			return st.SendAndClose(&finding.Ack{Accepted: streamCount})
		}
		if err != nil {
			return err
		}

		out, err := protojson.MarshalOptions{}.Marshal(msg)
		if err != nil {
			return fmt.Errorf("marshaling finding: %w", err)
		}
		fmt.Println(string(out))
		streamCount++

		if total := c.received.Add(1); c.refuseAfter > 0 && total >= c.refuseAfter {
			return status.Error(codes.Unavailable, "refusing findings (--refuse-after reached)")
		}
	}
}
