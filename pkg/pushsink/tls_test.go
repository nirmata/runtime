package pushsink

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nirmata/runtime/pkg/proto/finding"
	"github.com/nirmata/runtime/pkg/reporter"

	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// testPKI is a throwaway CA and the two leaf certificates a mutual-TLS
// handshake needs, written to files because that is how the daemon is
// configured: chart-provisioned Secret mounts, not in-memory material.
type testPKI struct {
	caFile     string
	serverCert string
	serverKey  string
	clientCert string
	clientKey  string
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pushsink-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}

	pki := testPKI{
		caFile:     filepath.Join(dir, "ca.crt"),
		serverCert: filepath.Join(dir, "server.crt"),
		serverKey:  filepath.Join(dir, "server.key"),
		clientCert: filepath.Join(dir, "client.crt"),
		clientKey:  filepath.Join(dir, "client.key"),
	}
	writePEM(t, pki.caFile, "CERTIFICATE", caDER)

	// The sink dials 127.0.0.1, so the collector is named by IP rather than by
	// a DNS name it would never present.
	serverDER, serverKey := issueLeaf(t, ca, caKey, "collector", []net.IP{net.ParseIP("127.0.0.1")}, x509.ExtKeyUsageServerAuth)
	writePEM(t, pki.serverCert, "CERTIFICATE", serverDER)
	writeKey(t, pki.serverKey, serverKey)

	clientDER, clientKey := issueLeaf(t, ca, caKey, "daemon", nil, x509.ExtKeyUsageClientAuth)
	writePEM(t, pki.clientCert, "CERTIFICATE", clientDER)
	writeKey(t, pki.clientKey, clientKey)

	return pki
}

func issueLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, ips []net.IP, usage x509.ExtKeyUsage) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating %s key: %v", cn, err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating %s certificate: %v", cn, err)
	}
	return der, key
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func writeKey(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	writePEM(t, path, "EC PRIVATE KEY", der)
}

func (p testPKI) options(target string, loss lossRecord) Options {
	return Options{
		Target:    target,
		CAFile:    p.caFile,
		CertFile:  p.clientCert,
		KeyFile:   p.clientKey,
		QueueSize: 4,
		LossFunc:  loss.record,
	}
}

// recordingCollector is the receiving half of the RPC: it accepts a stream and
// publishes what arrives.
type recordingCollector struct {
	finding.UnimplementedFindingServiceServer
	received chan *finding.Finding
}

func (c *recordingCollector) Report(stream grpc.ClientStreamingServer[finding.Finding, finding.Ack]) error {
	var accepted uint64
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&finding.Ack{Accepted: accepted})
		}
		if err != nil {
			return err
		}
		accepted++
		c.received <- msg
	}
}

// startCollector serves the RPC over mutual TLS, requiring and verifying the
// daemon's client certificate.
func startCollector(t *testing.T, pki testPKI) (addr string, received chan *finding.Finding) {
	t.Helper()

	pair, err := tls.LoadX509KeyPair(pki.serverCert, pki.serverKey)
	if err != nil {
		t.Fatalf("loading server certificate: %v", err)
	}
	caPEM, err := os.ReadFile(pki.caFile)
	if err != nil {
		t.Fatalf("reading CA: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("test CA holds no certificate")
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	received = make(chan *finding.Finding, 8)
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientCAs:    roots,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	})))
	finding.RegisterFindingServiceServer(srv, &recordingCollector{received: received})

	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(lis)
	}()
	t.Cleanup(func() {
		srv.Stop()
		<-served
	})

	return lis.Addr().String(), received
}

// The end-to-end path: a finding reported on the event path reaches a
// collector that demands a client certificate, and arrives redacted.
func TestReportedFindingsReachTheCollectorOverMutualTLS(t *testing.T) {
	pki := newTestPKI(t)
	addr, received := startCollector(t, pki)

	loss := lossRecord{}
	s, err := New(logr.Discard(), pki.options(addr, loss))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	f := findingNamed("block-exec")
	f.Message = "exec carrying sk-ant-api03-aaaabbbbccccdddd"
	s.Report(f)

	got := <-received
	if got.GetPolicyName() != "block-exec" {
		t.Errorf("policy name = %q, want block-exec", got.GetPolicyName())
	}
	if want := "exec carrying " + reporter.Redacted; got.GetMessage() != want {
		t.Errorf("message = %q, want %q", got.GetMessage(), want)
	}
	if got.GetPod().GetNamespace() != "default" {
		t.Errorf("pod namespace = %q, want default", got.GetPod().GetNamespace())
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run returned %v, want nil on shutdown", err)
	}
	if len(loss) != 0 {
		t.Errorf("loss recorded on a healthy stream: %v", loss)
	}
}

// Findings observed just before shutdown are sent, not abandoned in the queue.
func TestShutdownDrainsTheQueue(t *testing.T) {
	pki := newTestPKI(t)
	addr, received := startCollector(t, pki)

	s, err := New(logr.Discard(), pki.options(addr, lossRecord{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	// The first finding establishes the stream, so the rest are queued against
	// a connection the shutdown drain can still use.
	s.Report(findingNamed("first"))
	<-received
	s.Report(findingNamed("second"))
	cancel()

	if got := (<-received).GetPolicyName(); got != "second" {
		t.Errorf("drained finding = %q, want second", got)
	}
	if err := <-done; err != nil {
		t.Errorf("Run returned %v, want nil on shutdown", err)
	}
}

func TestNewRequiresATargetAndCompleteTLSMaterial(t *testing.T) {
	pki := newTestPKI(t)
	full := pki.options("collector.example:443", lossRecord{})

	tests := []struct {
		name string
		opts func(Options) Options
		want string
	}{
		{"no target", func(o Options) Options { o.Target = ""; return o }, "no target"},
		{"no ca", func(o Options) Options { o.CAFile = ""; return o }, "--push-tls-ca"},
		{"no certificate", func(o Options) Options { o.CertFile = ""; return o }, "--push-tls-cert"},
		{"no key", func(o Options) Options { o.KeyFile = ""; return o }, "--push-tls-key"},
		{"unreadable ca", func(o Options) Options { o.CAFile = filepath.Join(t.TempDir(), "absent.crt"); return o }, "reading collector CA"},
		{"ca holds no certificate", func(o Options) Options { o.CAFile = emptyFile(t); return o }, "holds no certificate"},
		{"unreadable certificate", func(o Options) Options { o.CertFile = emptyFile(t); return o }, "loading client certificate"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(logr.Discard(), tc.opts(full))
			if err == nil {
				t.Fatal("New succeeded; incomplete TLS material must never yield a sink")
			}
			if s != nil {
				t.Error("New returned a sink alongside an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name %q", err, tc.want)
			}
		})
	}
}

// The credentials this sink builds are TLS. There is no option, and no failure
// of one, that produces an insecure transport instead.
func TestLoadedCredentialsAreTLS(t *testing.T) {
	pki := newTestPKI(t)
	creds, err := loadCredentials(pki.options("collector.example:443", lossRecord{}))
	if err != nil {
		t.Fatalf("loadCredentials: %v", err)
	}
	if got := creds.Info().SecurityProtocol; got != "tls" {
		t.Errorf("security protocol = %q, want tls", got)
	}
}

func emptyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}
