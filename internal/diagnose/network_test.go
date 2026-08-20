package diagnose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/drvoss/pingcert/internal/model"
)

func TestCertificateResultValidAndHostnameMismatch(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	root, leaf, roots := makeChain(t, now, "example.test")
	target := model.Target{Host: "example.test", ServerName: "example.test"}

	got := certificateResult(leaf, []*x509.Certificate{root}, target, roots, now, 30*24*time.Hour, 0)
	if got.Status != model.StatusOK || got.HostnameMatch == nil || !*got.HostnameMatch ||
		got.ChainValid == nil || !*got.ChainValid {
		t.Fatalf("valid certificate rejected: %+v", got)
	}

	target.ServerName = "wrong.test"
	got = certificateResult(leaf, []*x509.Certificate{root}, target, roots, now, 30*24*time.Hour, 0)
	if got.Status != model.StatusFail || got.HostnameMatch == nil || *got.HostnameMatch {
		t.Fatalf("hostname mismatch accepted: %+v", got)
	}
}

func TestCertificateExpiryPolicy(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	root, leaf, roots := makeChain(t, now, "example.test")
	leaf.NotAfter = now.Add(5 * 24 * time.Hour)
	target := model.Target{Host: "example.test", ServerName: "example.test"}

	got := certificateResult(leaf, []*x509.Certificate{root}, target, roots, now, 30*24*time.Hour, 0)
	// The parsed certificate signature still contains the original validity;
	// policy reads the object field, while chain verification remains valid.
	if got.Status != model.StatusWarn {
		t.Fatalf("expected warning: %+v", got)
	}
	got = certificateResult(leaf, []*x509.Certificate{root}, target, roots, now, 30*24*time.Hour, 7*24*time.Hour)
	if got.Status != model.StatusFail {
		t.Fatalf("expected policy failure: %+v", got)
	}
}

func makeChain(t *testing.T, now time.Time, hostname string) (*x509.Certificate, *x509.Certificate, *x509.CertPool) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PingCert Test Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return root, leaf, roots
}
