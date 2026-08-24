package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
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
