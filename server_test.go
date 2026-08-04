package ldaps

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const (
	timeout      = 100 * time.Millisecond
	serverBaseDN = "o=testers,c=test"
)

type selfSignedCert struct {
	// Path to the SSL certificates.
	CACertPath, CertPath string

	// Path to the private keys for the SSL certificates.
	CAKeyPath, KeyPath string
}

// ListenAndServe starts s in a new go routine. It ensures that s is listening before returning the address the server is listening on
func ListenAndServe(t *testing.T, s *Server) (net.Addr, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	go func() {
		if err := s.Serve(ln); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()
	return ln.Addr(), nil
}

func newSelfSignedCert(t *testing.T) *selfSignedCert {
	tempDir := t.TempDir()
	capk, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}

	caSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: caSerial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(7 * 24 * time.Hour),

		KeyUsage:    x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,

		Subject: pkix.Name{
			Organization: []string{"my_test_ca"},
			CommonName:   "My Test CA",
		},

		IsCA: true,
	}

	caCert, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, capk.Public(), capk)
	if err != nil {
		panic(err)
	}
	// fmt.Printf("CA CERT\n%#v\n", caCert)
	caCertPEM := &pem.Block{Type: "CERTIFICATE", Bytes: caCert}
	caCertFile, err := os.CreateTemp(tempDir, "cacert-*.pem")
	if err != nil {
		panic(err)
	}
	if err := pem.Encode(caCertFile, caCertPEM); err != nil {
		panic(err)
	}
	caCertFile.Close()

	caKeyFile, err := os.CreateTemp(tempDir, "cakey-*.pem")
	if err != nil {
		panic(err)
	}
	if err := pem.Encode(caKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(capk)}); err != nil {
		panic(err)
	}
	caKeyFile.Close()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	// Basically the same as the CA template, but its own serial, and with ip addresses and dns names.
	template := x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(7 * 24 * time.Hour),

		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,

		Subject: pkix.Name{
			CommonName: "localhost",
		},

		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:    []string{"localhost"},
	}

	pk, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	cert, err := x509.CreateCertificate(rand.Reader, &template, &caTemplate, pk.Public(), capk)
	if err != nil {
		panic(err)
	}
	certPEM := &pem.Block{Type: "CERTIFICATE", Bytes: cert}
	certFile, err := os.CreateTemp(tempDir, "sslcert-*.pem")
	if err != nil {
		panic(err)
	}
	if err := pem.Encode(certFile, certPEM); err != nil {
		panic(err)
	}
	certFile.Close()

	keyFile, err := os.CreateTemp(tempDir, "key-*.pem")
	if err != nil {
		panic(err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)}); err != nil {
		panic(err)
	}
	keyFile.Close()

	return &selfSignedCert{
		CACertPath: caCertFile.Name(),
		CAKeyPath:  caKeyFile.Name(),
		CertPath:   certFile.Name(),
		KeyPath:    keyFile.Name(),
	}
}

func (c *selfSignedCert) cleanup() {
	os.RemoveAll(c.CertPath)
	os.RemoveAll(c.CACertPath)
	os.RemoveAll(c.KeyPath)
	os.RemoveAll(c.CAKeyPath)
}

func (c *selfSignedCert) ClientTLSConfig() *tls.Config {
	cert, err := os.ReadFile(c.CACertPath)
	if err != nil {
		panic(err)
	}

	// Return a TLS config that trusts our self-generated CA.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cert) {
		panic("failed to append certificate")
	}
	return &tls.Config{
		RootCAs: pool,
	}
}

func (c *selfSignedCert) ServerTLSConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair(c.CertPath, c.KeyPath)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		ServerName:   "localhost",
		Certificates: []tls.Certificate{cert},
	}
}

func TestStartTLS(t *testing.T) {
	if runtime.GOOS == "darwin" {
		defer func() {
			if t.Failed() {
				t.Logf(`NOTE: this test won't pass with the built-in Mac ldap utilities.
Work around this by using brew install openldap, and running the test as PATH=/usr/local/opt/openldap/bin:$PATH go test.

This test uses environment variables that are respected by OpenLDAP, but the Mac utilities don't let you override
security settings through environment variables; they expect certificates to be added to the system keychain,
which is very heavy-handed for a test like this.
`)
			}
		}()
	}
	cert := newSelfSignedCert(t)
	defer cert.cleanup()

	s := NewServer()
	s.BindFunc("", bindAnonOK{})
	s.SearchFunc("", searchSimple{})

	s.TLSConfig = cert.ServerTLSConfig()

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Errorf("Failed to listen")
		return
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx,
		"ldapsearch",
		"-H", "ldap://"+addr.String(),
		"-ZZ", // Force TLS
		"-d", "-1",
		"-x",
		"-b", "o=testers,c=test")

	// We don't care about testing validity we just want TLS to work
	cmd.Env = append(os.Environ(), "LDAPTLS_REQCERT=ALLOW")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Error(err)
	}

	if !strings.Contains(string(out), "# numEntries: 3") || !strings.Contains(string(out), "result: 0 Success") {
		t.Errorf("search did not succeed:\n%s", out)
	}
}

func TestBindAnonOK(t *testing.T) {
	s := NewServer()
	s.SearchFunc("", searchSimple{})
	s.BindFunc("", bindAnonOK{})

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Errorf("Failed to listen")
		return
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ldapsearch", "-v", "-H", "ldap://"+addr.String(), "-x", "-b", serverBaseDN)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapsearch failed: %v", err)
	}
	if !strings.Contains(string(out), "result: 0 Success") {
		t.Errorf("ldapsearch failed: %s", out)
	}
}

func TestBindAnonFail(t *testing.T) {
	previousOutput := log.Writer()
	log.SetOutput(t.Output())

	t.Cleanup(func() { log.SetOutput(previousOutput) })
	s := NewServer()
	s.BindFunc("", bindSimple{})

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Errorf("Failed to listen")
		return
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x", "-b", serverBaseDN)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Errorf("ldapsearch succeed. It shouldn't have: %s", out)
	}
	if !strings.Contains(string(out), "ldap_bind: Invalid credentials (49)") {
		t.Errorf("ldapsearch failed: %s", out)
	}
}

func TestBindSimpleOK(t *testing.T) {
	s := NewServer()
	s.SearchFunc("", searchSimple{})
	s.BindFunc("", bindSimple{})

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Errorf("Failed to listen")
		return
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x",
		"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapsearch failed: %v", err)
	}
	if !strings.Contains(string(out), "result: 0 Success") {
		t.Errorf("ldapsearch failed: %s", out)
	}
}

func TestBindSimpleFailBadPw(t *testing.T) {
	previousOutput := log.Writer()
	log.SetOutput(t.Output())

	t.Cleanup(func() { log.SetOutput(previousOutput) })
	s := NewServer()
	s.BindFunc("", bindSimple{})

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Errorf("Failed to listen")
		return
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x",
		"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "BADPassword")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Errorf("ldapsearch succeed. It shouldn't have: %s", out)
	}
	if !strings.Contains(string(out), "ldap_bind: Invalid credentials (49)") {
		t.Errorf("ldapsearch succeeded - should have failed: %s", out)
	}
}

func TestBindSimpleFailBadDn(t *testing.T) {
	previousOutput := log.Writer()
	log.SetOutput(t.Output())

	t.Cleanup(func() { log.SetOutput(previousOutput) })
	s := NewServer()
	s.BindFunc("", bindSimple{})

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Errorf("Failed to listen")
		return
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x",
		"-b", serverBaseDN, "-D", "cn=testoy,"+serverBaseDN, "-w", "iLike2test")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Errorf("ldapsearch succeed. It shouldn't have: %s", out)
	}
	if string(out) != "ldap_bind: Invalid credentials (49)\n" {
		t.Errorf("ldapsearch succeeded - should have failed: %s", out)
	}
}

func TestBindPanic(t *testing.T) {
	previousOutput := log.Writer()
	log.SetOutput(t.Output())

	t.Cleanup(func() { log.SetOutput(previousOutput) })

	s := NewServer()
	s.BindFunc("", bindPanic{})

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Errorf("Failed to listen")
		return
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x", "-b", serverBaseDN)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Errorf("ldapsearch succeed. It shouldn't have: %s", out)
	}
	if !strings.Contains(string(out), "ldap_bind: Operations error") {
		t.Errorf("ldapsearch should have returned operations error due to panic: %s", out)
	}
}

type testStatsWriter struct {
	buffer *bytes.Buffer
}

func (tsw testStatsWriter) Write(buf []byte) (int, error) {
	tsw.buffer.Write(buf)
	return len(buf), nil
}

func TestSearchStats(t *testing.T) {
	w := testStatsWriter{&bytes.Buffer{}}
	log.SetOutput(w)

	s := NewServer()

	s.SearchFunc("", searchSimple{})
	s.BindFunc("", bindAnonOK{})
	s.SetStats(true)

	addr, err := ListenAndServe(t, s)
	if err != nil {
		t.Errorf("Failed to listen")
		return
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ldapsearch", "-H", "ldap://"+addr.String(), "-x", "-b", serverBaseDN)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapsearch failed: %v", err)
	}
	if !strings.Contains(string(out), "result: 0 Success") {
		t.Errorf("ldapsearch failed: %s", out)
	}

	stats := s.GetStats()
	log.Println(stats)
	if stats.Conns != 1 || stats.Binds != 1 {
		t.Errorf("Stats data missing or incorrect: %v", w.buffer.String())
	}
}

type bindAnonOK struct{}

func (b bindAnonOK) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint16, error) {
	if bindDN == "" && bindSimplePw == "" {
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInvalidCredentials, nil
}

type bindSimple struct{}

func (b bindSimple) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint16, error) {
	if bindDN == "cn=testy,o=testers,c=test" && bindSimplePw == "iLike2test" {
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInvalidCredentials, nil
}

type bindSimple2 struct{}

func (b bindSimple2) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint16, error) {
	if bindDN == "cn=testy,o=testers,c=testz" && bindSimplePw == "ZLike2test" {
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInvalidCredentials, nil
}

type bindPanic struct{}

func (b bindPanic) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint16, error) {
	panic("test panic at the disco")
}

type bindCaseInsensitive struct{}

func (b bindCaseInsensitive) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint16, error) {
	if strings.ToLower(bindDN) == "cn=case,o=testers,c=test" && bindSimplePw == "iLike2test" {
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInvalidCredentials, nil
}

type searchSimple struct{}

func (s searchSimple) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*ldap.Entry{
		ldap.NewEntry("cn=ned,o=testers,c=test", map[string][]string{
			"cn":            {"ned"},
			"o":             {"ate"},
			"uidNumber":     {"5000"},
			"accountstatus": {"active"},
			"uid":           {"ned"},
			"description":   {"ned via sa"},
			"objectclass":   {"posixaccount"},
		}),
		ldap.NewEntry("cn=trent,o=testers,c=test", map[string][]string{
			"cn":            {"trent"},
			"o":             {"ate"},
			"uidNumber":     {"5005"},
			"accountstatus": {"active"},
			"uid":           {"trent"},
			"description":   {"trent via sa"},
			"objectclass":   {"posixaccount"},
		}),
		ldap.NewEntry("cn=randy,o=testers,c=test", map[string][]string{
			"cn":            {"randy"},
			"o":             {"ate"},
			"uidNumber":     {"5555"},
			"accountstatus": {"active"},
			"uid":           {"randy"},
			"objectclass":   {"posixaccount"},
		}),
	}

	return ServerSearchResult{
		Entries: entries, Referrals: []string{}, Controls: []ldap.Control{},
	}, nil
}

type searchSimple2 struct{}

func (s searchSimple2) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*ldap.Entry{
		ldap.NewEntry("cn=hamburger,o=testers,c=testz", map[string][]string{
			"cn":            {"hamburger"},
			"o":             {"testers"},
			"uidNumber":     {"5000"},
			"accountstatus": {"active"},
			"uid":           {"hamburger"},
			"objectclass":   {"posixaccount"},
		}),
	}

	return ServerSearchResult{
		Entries: entries, Referrals: []string{}, Controls: []ldap.Control{},
	}, nil
}

type searchPanic struct{}

func (s searchPanic) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	panic("this is a test panic")
}

type searchControls struct{}

func (s searchControls) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*ldap.Entry{}
	if len(searchReq.Controls) == 1 && searchReq.Controls[0].GetControlType() == "1.2.3.4.5" {
		newEntry := &ldap.Entry{DN: "cn=hamburger,o=testers,c=testz", Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"hamburger"}},
			{Name: "o", Values: []string{"testers"}},
			{Name: "uidNumber", Values: []string{"5000"}},
			{Name: "accountstatus", Values: []string{"active"}},
			{Name: "uid", Values: []string{"hamburger"}},
			{Name: "objectclass", Values: []string{"posixaccount"}},
		}}
		entries = append(entries, newEntry)
	}
	return ServerSearchResult{entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
}

type searchCaseInsensitive struct{}

func (s searchCaseInsensitive) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*ldap.Entry{
		{DN: "cn=CASE,o=testers,c=test", Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"CaSe"}},
			{Name: "o", Values: []string{"ate"}},
			{Name: "uidNumber", Values: []string{"5005"}},
			{Name: "accountstatus", Values: []string{"active"}},
			{Name: "uid", Values: []string{"trent"}},
			{Name: "description", Values: []string{"trent via sa"}},
			{Name: "objectclass", Values: []string{"posixaccount"}},
		}},
	}
	return ServerSearchResult{entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
}

func TestRouteFunc(t *testing.T) {
	if routeFunc("", []string{"a", "xyz", "tt"}) != "" {
		t.Error("routeFunc failed")
	}
	if routeFunc("a=b", []string{"a=b", "x=y,a=b", "tt"}) != "a=b" {
		t.Error("routeFunc failed")
	}
	if routeFunc("x=y,a=b", []string{"a=b", "x=y,a=b", "tt"}) != "x=y,a=b" {
		t.Error("routeFunc failed")
	}
	if routeFunc("x=y,a=b", []string{"x=y,a=b", "a=b", "tt"}) != "x=y,a=b" {
		t.Error("routeFunc failed")
	}
	if routeFunc("nosuch", []string{"x=y,a=b", "a=b", "tt"}) != "" {
		t.Error("routeFunc failed")
	}
}

// mustListen returns a net.Listener listening on a random port.
func mustListen() (ln net.Listener, actualAddr string) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}

	return ln, ln.Addr().String()
}
