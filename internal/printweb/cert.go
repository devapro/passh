package printweb

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/devapro/passh/internal/i18n"
)

const (
	certDirName = "print-web"
	certFile    = "cert.pem"
	keyFile     = "key.pem"
	// certValidity is how long a new certificate is valid (§7.4).
	certValidity = 365 * 24 * time.Hour
	// certRenewBefore: a certificate this close to its end is replaced, so
	// it can't expire while the page is up.
	certRenewBefore = 24 * time.Hour
)

// certInfo is the print page's certificate.
type certInfo struct {
	pair        tls.Certificate
	leaf        *x509.Certificate
	fingerprint string       // SHA-256 of the DER, colon hex
	notice      i18n.Message // why a new one was made; zero when reused
}

// Fingerprint returns the SHA-256 fingerprint of a DER certificate as
// browsers show it: upper-case hex pairs separated by colons.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// loadOrCreateCert returns the certificate kept in dir if it is usable for
// addrs and hostnames at now, or makes, stores and returns a new one
// (self-signed ECDSA P-256, valid for a year, SANs = addrs + hostnames).
//
// The stored certificate is reused, so its fingerprint stays the same,
// unless it can't be read, its key file is readable by others, it expires
// within a day (or isn't valid yet), or it doesn't cover every address and
// hostname. A certificate that covers more than the current addresses is
// still reused, so an interface that is down for a while doesn't change the
// fingerprint.
//
// dir is created with mode 0700 (its parent too, if missing); the key file
// has mode 0600.
func loadOrCreateCert(dir string, addrs []netip.Addr, hostnames []string, now time.Time) (*certInfo, error) {
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	certPath, keyPath := filepath.Join(dir, certFile), filepath.Join(dir, keyFile)
	ci, reason := checkStored(certPath, keyPath, addrs, hostnames, now)
	if reason.IsZero() {
		return ci, nil
	}
	ci, err := createCert(dir, addrs, hostnames, now)
	if err != nil {
		return nil, err
	}
	ci.notice = i18n.Msg("made a new certificate for the print page (%s); "+
		"browsers will warn about it: compare the fingerprint", reason)
	return ci, nil
}

// checkStored returns the stored certificate, or why it can't be reused
// (a zero Message when it can).
func checkStored(certPath, keyPath string, addrs []netip.Addr, hostnames []string, now time.Time) (*certInfo, i18n.Message) {
	_, errC := os.Lstat(certPath)
	ki, errK := os.Lstat(keyPath)
	switch {
	case errors.Is(errC, fs.ErrNotExist) && errors.Is(errK, fs.ErrNotExist):
		return nil, i18n.Msg("first use")
	case errC != nil:
		return nil, i18n.Msg("the stored certificate can't be read: %v", errC)
	case errK != nil:
		return nil, i18n.Msg("the stored key can't be read: %v", errK)
	case !ki.Mode().IsRegular():
		return nil, i18n.Msg("the stored key is not a regular file")
	case ki.Mode().Perm()&0o077 != 0:
		return nil, i18n.Msg("the stored key had mode %04o, readable by others", ki.Mode().Perm())
	}
	ci, err := readCert(certPath, keyPath)
	if err != nil {
		return nil, i18n.Msg("the stored certificate can't be used: %v", err)
	}
	leaf := ci.leaf
	switch {
	case now.Before(leaf.NotBefore):
		return nil, i18n.Msg("the stored certificate is not valid until %s", leaf.NotBefore.Format(time.DateOnly))
	case now.After(leaf.NotAfter):
		return nil, i18n.Msg("the stored certificate expired on %s", leaf.NotAfter.Format(time.DateOnly))
	case now.Add(certRenewBefore).After(leaf.NotAfter):
		return nil, i18n.Msg("the stored certificate expires on %s", leaf.NotAfter.Format(time.DateOnly))
	}
	var missing []string
	for _, a := range addrs {
		if !slices.ContainsFunc(leaf.IPAddresses, func(ip net.IP) bool {
			b, ok := netip.AddrFromSlice(ip)
			return ok && b.Unmap() == a
		}) {
			missing = append(missing, a.String())
		}
	}
	for _, h := range hostnames {
		if !slices.ContainsFunc(leaf.DNSNames, func(n string) bool { return strings.EqualFold(n, h) }) {
			missing = append(missing, h)
		}
	}
	if len(missing) > 0 {
		return nil, i18n.Msg("the addresses or hostnames changed: the old one doesn't cover %s", strings.Join(missing, ", "))
	}
	return ci, i18n.Message{}
}

// readCert loads and checks a certificate and its key.
func readCert(certPath, keyPath string) (*certInfo, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	leaf := pair.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
			return nil, err
		}
	}
	if k, ok := pair.PrivateKey.(*ecdsa.PrivateKey); !ok || k.Curve != elliptic.P256() {
		return nil, i18n.NewError("not an ECDSA P-256 key")
	}
	return &certInfo{pair: pair, leaf: leaf, fingerprint: Fingerprint(leaf.Raw)}, nil
}

// createCert makes a new self-signed certificate and stores it in dir.
func createCert(dir string, addrs []netip.Addr, hostnames []string, now time.Time) (*certInfo, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, i18n.Errorf("print page certificate: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, i18n.Errorf("print page certificate: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "passh print page"},
		NotBefore:             now.Add(-time.Hour), // some clock skew
		NotAfter:              now.Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              slices.Clone(hostnames),
	}
	for _, a := range addrs {
		tmpl.IPAddresses = append(tmpl.IPAddresses, a.AsSlice())
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, i18n.Errorf("print page certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, i18n.Errorf("print page certificate: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := writeFileAtomic(dir, keyFile, keyPEM); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(dir, certFile, certPEM); err != nil {
		return nil, err
	}
	return readCert(filepath.Join(dir, certFile), filepath.Join(dir, keyFile))
}

// ensurePrivateDir creates dir with mode 0700, and its parent (the state
// folder) with 0700 if missing. An existing dir must be a folder, not a
// symlink; its mode is set to 0700.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return i18n.Errorf("print page certificate folder: %w", err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return i18n.Errorf("print page certificate folder: %w", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return i18n.Errorf("print page certificate folder: %w", err)
	}
	if !fi.IsDir() {
		return i18n.Errorf("print page certificate folder %s is not a folder", dir)
	}
	if fi.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return i18n.Errorf("print page certificate folder: %w", err)
		}
	}
	return nil
}

// writeFileAtomic writes data to dir/name with mode 0600 through a
// temporary file and a rename.
func writeFileAtomic(dir, name string, data []byte) (err error) {
	f, err := os.CreateTemp(dir, ".tmp-"+name+"-*")
	if err != nil {
		return i18n.Errorf("print page certificate: %w", err)
	}
	defer func() {
		if err != nil {
			// Best-effort cleanup of a temporary file that holds nothing
			// yet or a certificate nobody uses; err says what went wrong.
			_ = f.Close()
			_ = os.Remove(f.Name())
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		return i18n.Errorf("print page certificate: %w", err)
	}
	if _, err = f.Write(data); err != nil {
		return i18n.Errorf("print page certificate: %w", err)
	}
	if err = f.Sync(); err != nil {
		return i18n.Errorf("print page certificate: %w", err)
	}
	if err = f.Close(); err != nil {
		return i18n.Errorf("print page certificate: %w", err)
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, name)); err != nil {
		return i18n.Errorf("print page certificate: %w", err)
	}
	return nil
}
