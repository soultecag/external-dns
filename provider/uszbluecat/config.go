package uszbluecat

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
)

// loads TLS artifacts and builds tls.Config object
func newTLSConfig(certPath, keyPath, caPath, serverName string, insecure bool) (*tls.Config, error) {
	if certPath != "" && keyPath == "" || certPath == "" && keyPath != "" {
		return nil, errors.New("either both cert and key or none must be provided")
	}
	var certificates []tls.Certificate
	if certPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("could not load TLS cert: %w", err)
		}
		certificates = append(certificates, cert)
	}
	roots, err := loadRoots(caPath)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates:       certificates,
		RootCAs:            roots,
		InsecureSkipVerify: insecure,
		ServerName:         serverName,
	}, nil
}

// loads CA cert
func loadRoots(caPath string) (*x509.CertPool, error) {
	if caPath == "" {
		return nil, nil
	}

	roots := x509.NewCertPool()
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("error reading %s: %w", caPath, err)
	}
	ok := roots.AppendCertsFromPEM(pem)
	if !ok {
		return nil, fmt.Errorf("could not read root certs: %w", err)
	}
	return roots, nil
}

// builds etcd client config depending on connection scheme and TLS parameters
// TOTO: This is mock and just a copy core dns config
func getUszBlueCatConfig() (*Config, error) {
	uszBlueCatUrl := os.Getenv("USZ_BLUECAT_URL")
	if uszBlueCatUrl == "" {
		uszBlueCatUrl = "http://localhost:8080"
	}
	etcdURLs := strings.Split(uszBlueCatUrl, ",")
	firstURL := strings.ToLower(etcdURLs[0])
	etcdUsername := os.Getenv("USZ_BLUECAT_USERNAME")
	etcdPassword := os.Getenv("USZ_BLUECAT_PASSWORD")
	if strings.HasPrefix(firstURL, "http://") {
		return &Config{Endpoint: uszBlueCatUrl, Username: etcdUsername, Password: etcdPassword}, nil
	} else if strings.HasPrefix(firstURL, "https://") {
		caFile := os.Getenv("USZ_BLUECAT_CA_FILE")
		certFile := os.Getenv("USZ_BLUECAT_CERT_FILE")
		keyFile := os.Getenv("USZ_BLUECAT_KEY_FILE")
		serverName := os.Getenv("USZ_BLUECAT_TLS_SERVER_NAME")
		isInsecureStr := strings.ToLower(os.Getenv("USZ_BLUECAT_TLS_INSECURE"))
		isInsecure := isInsecureStr == "true" || isInsecureStr == "yes" || isInsecureStr == "1"
		tlsConfig, err := newTLSConfig(certFile, keyFile, caFile, serverName, isInsecure)
		if err != nil {
			return nil, err
		}
		return &Config{
			Endpoint: uszBlueCatUrl,
			TLS:      tlsConfig,
			Username: etcdUsername,
			Password: etcdPassword,
		}, nil
	} else {
		return nil, errors.New("etcd URLs must start with either http:// or https://")
	}
}
