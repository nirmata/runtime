package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nirmata/runtime/pkg/proto/finding"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func writeSelfSignedCert(t *testing.T, dir, name string) (certPath, keyPath string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}

	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("writing certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	return certPath, keyPath
}

func TestServerCredentialsPlaintext(t *testing.T) {
	creds, mode, err := serverCredentials("", "", "")
	if err != nil {
		t.Fatalf("serverCredentials: %v", err)
	}
	if creds != nil {
		t.Fatalf("expected nil credentials for plaintext mode, got %v", creds)
	}
	if mode != "plaintext" {
		t.Fatalf("mode = %q, want plaintext", mode)
	}
}

func TestServerCredentialsCertWithoutClientCA(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir, "server")

	creds, mode, err := serverCredentials(certPath, keyPath, "")
	if err != nil {
		t.Fatalf("serverCredentials: %v", err)
	}
	if creds == nil {
		t.Fatal("expected non-nil credentials")
	}
	if mode != "TLS" {
		t.Fatalf("mode = %q, want TLS", mode)
	}
}

func TestServerCredentialsClientCAWithNoValidCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir, "server")

	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("writing CA file: %v", err)
	}

	if _, _, err := serverCredentials(certPath, keyPath, caPath); err == nil {
		t.Fatal("expected an error for a client CA file with no valid certificate")
	}
}

func TestServerCredentialsRejectsMismatchedCertAndKeyFlags(t *testing.T) {
	if _, _, err := serverCredentials("cert.pem", "", ""); err == nil {
		t.Fatal("expected an error when only --tls-cert is set")
	}
	if _, _, err := serverCredentials("", "key.pem", ""); err == nil {
		t.Fatal("expected an error when only --tls-key is set")
	}
}

func TestServerCredentialsRejectsClientCAWithoutCertAndKey(t *testing.T) {
	if _, _, err := serverCredentials("", "", "ca.pem"); err == nil {
		t.Fatal("expected an error when --tls-client-ca is set without --tls-cert and --tls-key")
	}
}

// fakeReportStream stands in for grpc.ClientStreamingServer[finding.Finding,
// finding.Ack] so Report's Recv/SendAndClose logic can be tested without a
// real gRPC transport.
type fakeReportStream struct {
	msgs []*finding.Finding
	next int
	ack  *finding.Ack
}

func (f *fakeReportStream) Recv() (*finding.Finding, error) {
	if f.next >= len(f.msgs) {
		return nil, io.EOF
	}
	msg := f.msgs[f.next]
	f.next++
	return msg, nil
}

func (f *fakeReportStream) SendAndClose(ack *finding.Ack) error {
	f.ack = ack
	return nil
}

func (f *fakeReportStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeReportStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeReportStream) SetTrailer(metadata.MD)       {}
func (f *fakeReportStream) Context() context.Context     { return context.Background() }
func (f *fakeReportStream) SendMsg(any) error            { return nil }
func (f *fakeReportStream) RecvMsg(any) error            { return nil }

func findings(n int) []*finding.Finding {
	msgs := make([]*finding.Finding, n)
	for i := range msgs {
		msgs[i] = &finding.Finding{PolicyName: "policy"}
	}
	return msgs
}

func TestReportAcksExactlyRefuseAfterFindings(t *testing.T) {
	c := &collector{refuseAfter: 2}
	st := &fakeReportStream{msgs: findings(2)}

	if err := c.Report(st); err != nil {
		t.Fatalf("Report: %v", err)
	}
	if st.ack == nil || st.ack.GetAccepted() != 2 {
		t.Fatalf("ack = %v, want Accepted: 2", st.ack)
	}
	if got := c.received.Load(); got != 2 {
		t.Fatalf("received = %d, want 2", got)
	}
}

func TestReportRefusesTheFindingAfterRefuseAfterIsReached(t *testing.T) {
	c := &collector{refuseAfter: 2}
	st := &fakeReportStream{msgs: findings(3)}

	err := c.Report(st)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("Report err = %v, want an Unavailable status", err)
	}
	if st.ack != nil {
		t.Fatalf("expected no ack when the stream is refused, got %v", st.ack)
	}
	if got := c.received.Load(); got != 2 {
		t.Fatalf("received = %d, want 2 (the third finding must not be counted)", got)
	}
}

func TestReportRefusesANewStreamOnceRefuseAfterIsAlreadyReached(t *testing.T) {
	c := &collector{refuseAfter: 1}
	c.received.Store(1)
	st := &fakeReportStream{msgs: findings(1)}

	err := c.Report(st)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("Report err = %v, want an Unavailable status", err)
	}
	if st.next != 0 {
		t.Fatal("expected Report to refuse before calling Recv")
	}
}
