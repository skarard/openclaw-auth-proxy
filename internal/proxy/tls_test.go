package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestGenerateCA(t *testing.T) {
	certPEM, keyPEM, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("empty PEM output")
	}

	cm, err := NewCertManager(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}

	// Verify CA properties
	if !cm.caCert.IsCA {
		t.Error("CA cert IsCA should be true")
	}
	if cm.caCert.BasicConstraintsValid != true {
		t.Error("CA cert BasicConstraintsValid should be true")
	}
	if cm.caCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA cert should have KeyUsageCertSign")
	}
	if cm.caCert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("CA cert should have KeyUsageCRLSign")
	}
	if cm.caCert.Subject.CommonName != "OpenClaw Auth Proxy CA" {
		t.Errorf("unexpected CN: %s", cm.caCert.Subject.CommonName)
	}
}

func TestGetCertificateForHost(t *testing.T) {
	certPEM, keyPEM, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	cm, err := NewCertManager(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}

	cert, err := cm.GetCertificateForHost("api.github.com")
	if err != nil {
		t.Fatalf("GetCertificateForHost: %v", err)
	}

	// Verify SANs
	if len(cert.Leaf.DNSNames) != 1 || cert.Leaf.DNSNames[0] != "api.github.com" {
		t.Errorf("unexpected SANs: %v", cert.Leaf.DNSNames)
	}

	// Verify signed by CA
	pool := x509.NewCertPool()
	pool.AddCert(cm.caCert)
	_, err = cert.Leaf.Verify(x509.VerifyOptions{
		Roots: pool,
	})
	if err != nil {
		t.Errorf("cert not valid for CA: %v", err)
	}
}

func TestCertificateCaching(t *testing.T) {
	certPEM, keyPEM, _ := GenerateCA()
	cm, _ := NewCertManager(certPEM, keyPEM)

	cert1, _ := cm.GetCertificateForHost("example.com")
	cert2, _ := cm.GetCertificateForHost("example.com")

	if cert1 != cert2 {
		t.Error("expected same cert from cache")
	}
}

func TestDifferentHostsDifferentCerts(t *testing.T) {
	certPEM, keyPEM, _ := GenerateCA()
	cm, _ := NewCertManager(certPEM, keyPEM)

	cert1, _ := cm.GetCertificateForHost("a.com")
	cert2, _ := cm.GetCertificateForHost("b.com")

	if cert1 == cert2 {
		t.Error("expected different certs for different hosts")
	}
	if cert1.Leaf.DNSNames[0] != "a.com" {
		t.Errorf("cert1 SAN: %v", cert1.Leaf.DNSNames)
	}
	if cert2.Leaf.DNSNames[0] != "b.com" {
		t.Errorf("cert2 SAN: %v", cert2.Leaf.DNSNames)
	}
}

func TestGetCertificateViaTLSHello(t *testing.T) {
	certPEM, keyPEM, _ := GenerateCA()
	cm, _ := NewCertManager(certPEM, keyPEM)

	hello := &tls.ClientHelloInfo{ServerName: "test.example.com"}
	cert, err := cm.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert.Leaf.DNSNames[0] != "test.example.com" {
		t.Errorf("unexpected SAN: %v", cert.Leaf.DNSNames)
	}
}

func TestGetCertificateNoSNI(t *testing.T) {
	certPEM, keyPEM, _ := GenerateCA()
	cm, _ := NewCertManager(certPEM, keyPEM)

	hello := &tls.ClientHelloInfo{ServerName: ""}
	_, err := cm.GetCertificate(hello)
	if err == nil {
		t.Error("expected error for empty SNI")
	}
}
