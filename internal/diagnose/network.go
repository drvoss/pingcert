package diagnose

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/drvoss/pingcert/internal/model"
)

type Family int

const (
	FamilyAny Family = iota
	FamilyIPv4
	FamilyIPv6
)

type Network struct {
	Resolver *net.Resolver
	Dialer   *net.Dialer
	Now      func() time.Time
	Roots    *x509.CertPool
}

func NewNetwork(timeout time.Duration) *Network {
	return &Network{
		Resolver: net.DefaultResolver,
		Dialer:   &net.Dialer{Timeout: timeout},
		Now:      time.Now,
	}
}

func (n *Network) Resolve(ctx context.Context, target *model.Target, family Family) model.DNSResult {
	start := n.Now()
	result := model.DNSResult{Status: model.StatusFail, Host: target.Host}
	resolveCtx, cancel := context.WithTimeout(ctx, n.Dialer.Timeout)
	defer cancel()
	addrs, err := n.Resolver.LookupIPAddr(resolveCtx, target.Host)
	result.Elapsed = n.Now().Sub(start).Milliseconds()
	if err != nil {
		result.Error = err.Error()
		return result
	}

	seen := map[string]bool{}
	for _, addr := range addrs {
		ip := addr.IP
		if family == FamilyIPv4 && ip.To4() == nil {
			continue
		}
		if family == FamilyIPv6 && ip.To4() != nil {
			continue
		}
		s := ip.String()
		if !seen[s] {
			result.IPs = append(result.IPs, s)
			seen[s] = true
		}
	}
	if len(result.IPs) == 0 {
		result.Error = "no address matched the requested family"
		return result
	}
	result.Selected = result.IPs[0]
	if net.ParseIP(result.Selected).To4() != nil {
		result.Family = "ipv4"
	} else {
		result.Family = "ipv6"
	}
	result.Status = model.StatusOK
	target.Addresses = append([]string(nil), result.IPs...)
	target.IP = result.Selected
	target.Family = result.Family
	return result
}

func (n *Network) TCPAndTLS(ctx context.Context, target model.Target, warnBefore, failBefore time.Duration) (model.TCPResult, model.TLSResult, model.CertificateResult) {
	address := net.JoinHostPort(target.IP, strconv.Itoa(target.Port))
	tcpResult := model.TCPResult{Status: model.StatusFail, Address: address}
	tlsResult := model.TLSResult{Status: model.StatusSkipped}
	certResult := model.CertificateResult{Status: model.StatusSkipped}

	start := n.Now()
	conn, err := n.Dialer.DialContext(ctx, "tcp", address)
	tcpResult.Elapsed = n.Now().Sub(start).Milliseconds()
	if err != nil {
		tcpResult.Error = shortError(err)
		return tcpResult, tlsResult, certResult
	}
	tcpResult.Status = model.StatusOK
	defer conn.Close()

	tlsStart := n.Now()
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         target.ServerName,
		InsecureSkipVerify: true, // Verification is performed explicitly below.
		MinVersion:         tls.VersionTLS12,
	})
	handshakeCtx, cancel := context.WithTimeout(ctx, n.Dialer.Timeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		tlsResult.Status = model.StatusFail
		tlsResult.Elapsed = n.Now().Sub(tlsStart).Milliseconds()
		tlsResult.Error = shortError(err)
		return tcpResult, tlsResult, certResult
	}
	state := tlsConn.ConnectionState()
	tlsResult.Status = model.StatusOK
	tlsResult.Version = tlsVersion(state.Version)
	tlsResult.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	tlsResult.ALPN = state.NegotiatedProtocol
	tlsResult.Elapsed = n.Now().Sub(tlsStart).Milliseconds()

	if len(state.PeerCertificates) == 0 {
		certResult.Status = model.StatusFail
		certResult.Error = "server returned no certificate"
		return tcpResult, tlsResult, certResult
	}

	leaf := state.PeerCertificates[0]
	certResult = certificateResult(leaf, state.PeerCertificates[1:], target, n.Roots, n.Now(), warnBefore, failBefore)
	return tcpResult, tlsResult, certResult
}

func certificateResult(leaf *x509.Certificate, chain []*x509.Certificate, target model.Target, roots *x509.CertPool, now time.Time, warnBefore, failBefore time.Duration) model.CertificateResult {
	sum := sha256.Sum256(leaf.Raw)
	result := model.CertificateResult{
		Status:       model.StatusOK,
		Subject:      nameOrDN(leaf.Subject.CommonName, leaf.Subject.String()),
		Issuer:       nameOrDN(leaf.Issuer.CommonName, leaf.Issuer.String()),
		SerialNumber: leaf.SerialNumber.String(),
		DNSNames:     append([]string(nil), leaf.DNSNames...),
		NotBefore:    timePointer(leaf.NotBefore),
		NotAfter:     timePointer(leaf.NotAfter),
		SHA256:       strings.ToUpper(hex.EncodeToString(sum[:])),
	}
	daysRemaining := int(math.Floor(leaf.NotAfter.Sub(now).Hours() / 24))
	result.DaysRemaining = &daysRemaining

	verifyName := target.ServerName
	if verifyName == "" {
		verifyName = target.Host
	}
	hostErr := leaf.VerifyHostname(verifyName)
	hostnameMatch := hostErr == nil
	result.HostnameMatch = &hostnameMatch

	intermediates := x509.NewCertPool()
	for _, cert := range chain {
		intermediates.AddCert(cert)
	}
	_, chainErr := leaf.Verify(x509.VerifyOptions{
		DNSName:       verifyName,
		Intermediates: intermediates,
		Roots:         roots,
		CurrentTime:   now,
	})
	chainValid := chainErr == nil
	result.ChainValid = &chainValid

	switch {
	case chainErr != nil:
		result.Status = model.StatusFail
		result.Error = shortError(chainErr)
	case hostErr != nil:
		result.Status = model.StatusFail
		result.Error = shortError(hostErr)
	case now.Before(leaf.NotBefore):
		result.Status = model.StatusFail
		result.Error = "certificate is not valid yet"
	case !now.Before(leaf.NotAfter):
		result.Status = model.StatusFail
		result.Error = "certificate has expired"
	case failBefore > 0 && leaf.NotAfter.Sub(now) <= failBefore:
		result.Status = model.StatusFail
		result.Error = fmt.Sprintf("certificate expires within %s", failBefore)
	case warnBefore > 0 && leaf.NotAfter.Sub(now) <= warnBefore:
		result.Status = model.StatusWarn
		result.Error = fmt.Sprintf("certificate expires within %s", warnBefore)
	}
	return result
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func shortError(err error) string {
	if err == nil {
		return ""
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return "timeout"
	}
	s := strings.ReplaceAll(err.Error(), "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 180 {
		return s[:177] + "..."
	}
	return s
}

func nameOrDN(commonName, full string) string {
	if commonName != "" {
		return commonName
	}
	return full
}

func timePointer(value time.Time) *time.Time {
	return &value
}
