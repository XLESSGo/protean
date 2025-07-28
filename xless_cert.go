// mimic_tls_certificate.go
// This file provides a standalone exported function for generating a mimic TLS certificate using protean.
// It is designed for use in your protean fork and can be imported as "github.com/XLESSGo/protean/mimic_tls_certificate".
// No other changes needed in your server logic.

package tls

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"time"
	"fmt"
	"strings"
	"encoding/base64"
	"crypto/x509/pkix"
)

// MimicTLSCertificate generates a mimic TLS certificate for the given SNI/domain list.
// It returns a *tls.Certificate ready for use in Go's TLS/QUIC server config.
// domains: SNI(s) you want to camouflage as (e.g. decoy domains).
// validityDays: certificate validity period in days (recommended: 365).
func MimicTLSCertificate(domains []string, validityDays int) (*tls.Certificate, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains provided")
	}

	// Pick the first domain as CommonName
	cn := strings.TrimSpace(domains[0])
	if cn == "" {
		return nil, fmt.Errorf("invalid domain")
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Generate RSA private key (2048 bits for compatibility and camouflage)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Certificate template
	notBefore := time.Now().Add(-time.Hour * 24) // Not before: yesterday
	notAfter := notBefore.Add(time.Duration(validityDays) * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Protean Mimic"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  false,
		BasicConstraintsValid: true,

		DNSNames: domains, // SAN support for all domains
	}

	// Self-sign the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode to PEM
	certPEM := encodeToPEM("CERTIFICATE", derBytes)
	keyPEM := encodeToPEM("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(priv))

	// Parse as Go TLS certificate
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load X509 keypair: %w", err)
	}

	return &tlsCert, nil
}

// encodeToPEM encodes DER bytes to PEM format with the given block type.
func encodeToPEM(blockType string, derBytes []byte) []byte {
	return []byte(fmt.Sprintf("-----BEGIN %s-----\n%s\n-----END %s-----\n",
		blockType,
		chunkString(base64.StdEncoding.EncodeToString(derBytes), 64),
		blockType,
	))
}

// chunkString splits an encoded string into lines of the given width (for PEM formatting).
func chunkString(s string, chunkSize int) string {
	var result strings.Builder
	for i := 0; i < len(s); i += chunkSize {
		end := i + chunkSize
		if end > len(s) {
			end = len(s)
		}
		result.WriteString(s[i:end])
		result.WriteByte('\n')
	}
	return result.String()
}
