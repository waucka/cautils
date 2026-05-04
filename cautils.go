package cautils

import (
	"errors"
	"fmt"
	"net"
	"time"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
)

const (
	caCertKeyUsage   = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	leafCertKeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
)

type CryptoAlgo int

func (c CryptoAlgo) String() string {
	switch c {
	case CryptoAlgoRsa4096:
		return "rsa4096"
	case CryptoAlgoEcdsaP256:
		return "ecdsap256"
	case CryptoAlgoEcdsaP384:
		return "ecdap384"
	default:
		return "unknown"
	}
}

const (
	CryptoAlgoRsa4096 CryptoAlgo = iota
	CryptoAlgoEcdsaP256
	CryptoAlgoEcdsaP384
)

type DigestAlgo int

func (c DigestAlgo) String() string {
	switch c {
	case DigestAlgoSha256:
		return "sha256"
	case DigestAlgoSha384:
		return "sha384"
	case DigestAlgoSha512:
		return "sha512"
	default:
		return "unknown"
	}
}

const (
	DigestAlgoSha256 DigestAlgo = iota
	DigestAlgoSha384
	DigestAlgoSha512
)

var (
	// DEAR GOD!  WHO THOUGHT THIS WAS A GOOD API?  WHY WHY WHY WHY WHY WHY WHY WHY WHY?
	maxSerial             = big.NewInt(0).Exp(big.NewInt(2), big.NewInt(159), nil)
	clientCertExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection}
	serverCertExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	ErrInvalidPrivateKey = errors.New("invalid private key")
)

func MarshalPrivateKey(privkey interface{}) ([]byte, error) {
	switch k := privkey.(type) {
	case *rsa.PrivateKey:
		return x509.MarshalPKCS1PrivateKey(k), nil
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return b, nil
	default:
		return nil, ErrInvalidPrivateKey
	}
}

func GenKeyPair(cryptoAlgo CryptoAlgo) (pubkey interface{}, privkey interface{}, generr error) {
	var err error
	pubkey = nil
	privkey = nil
	switch cryptoAlgo {
	case CryptoAlgoRsa4096:
		priv, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			generr = fmt.Errorf("failed to generate RSA keypair: %s", err.Error())
			return
		}
		pubkey = &priv.PublicKey
		privkey = priv
	case CryptoAlgoEcdsaP256:
		var priv *ecdsa.PrivateKey
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			generr = fmt.Errorf("failed to generate ECDSA keypair: %s", err.Error())
			return
		}
		pubkey = &priv.PublicKey
		privkey = priv
	case CryptoAlgoEcdsaP384:
		var priv *ecdsa.PrivateKey
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			generr = fmt.Errorf("failed to generate ECDSA keypair: %s", err.Error())
			return
		}
		pubkey = &priv.PublicKey
		privkey = priv
	}
	return
}

func Getx509SigAlgo(cryptoAlgo CryptoAlgo, digestAlgo DigestAlgo) (x509.SignatureAlgorithm, error) {
	var sigAlgo x509.SignatureAlgorithm
	if digestAlgo == DigestAlgoSha256 {
		if cryptoAlgo == CryptoAlgoRsa4096 {
			sigAlgo = x509.SHA256WithRSA
		} else if cryptoAlgo == CryptoAlgoEcdsaP256 || cryptoAlgo == CryptoAlgoEcdsaP384 {
			sigAlgo = x509.ECDSAWithSHA256
		} else {
			return sigAlgo, fmt.Errorf("invalid crypto/digest combination: %s/%s", cryptoAlgo, digestAlgo)
		}
	} else if digestAlgo == DigestAlgoSha384 {
		if cryptoAlgo == CryptoAlgoRsa4096 {
			sigAlgo = x509.SHA384WithRSA
		} else if cryptoAlgo == CryptoAlgoEcdsaP256 || cryptoAlgo == CryptoAlgoEcdsaP384 {
			sigAlgo = x509.ECDSAWithSHA384
		} else {
			return sigAlgo, fmt.Errorf("invalid crypto/digest combination: %s/%s", cryptoAlgo, digestAlgo)
		}
	} else if digestAlgo == DigestAlgoSha512 {
		if cryptoAlgo == CryptoAlgoRsa4096 {
			sigAlgo = x509.SHA512WithRSA
		} else if cryptoAlgo == CryptoAlgoEcdsaP256 || cryptoAlgo == CryptoAlgoEcdsaP384 {
			sigAlgo = x509.ECDSAWithSHA512
		} else {
			return sigAlgo, fmt.Errorf("invalid crypto/digest combination: %s/%s", cryptoAlgo, digestAlgo)
		}
	} else {
		return sigAlgo, fmt.Errorf("invalid digest algorithm: %s", digestAlgo)
	}
	return sigAlgo, nil
}

type CACertificateParameters struct {
	MaxPathLen int
}

type InternalCertificateRequest struct {
	SignatureAlgorithm x509.SignatureAlgorithm
	PublicKey          interface{}
	PrivateKey         interface{}
	Subject            pkix.Name
	KeyUsage           x509.KeyUsage
	ExtKeyUsage        []x509.ExtKeyUsage
	NotBefore          time.Time
	NotAfter           time.Time
	CAParams           *CACertificateParameters
	IPAddresses        []net.IP
	DNSNames           []string
}

func GenerateSignableCertififcate(req *InternalCertificateRequest) ([]byte, *x509.Certificate, error) {
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		SignatureAlgorithm: req.SignatureAlgorithm,
		Subject:            req.Subject,
		PublicKey:          req.PublicKey,
		IPAddresses:        req.IPAddresses,
		DNSNames:           req.DNSNames,
	}, req.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create internal CSR: %s", err.Error())
	}
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to reload internal CSR (this should never happen!): %s", err.Error())
	}
	certTemplate, err := certFromCsr(csr, req.KeyUsage, req.ExtKeyUsage, req.CAParams, req.NotBefore, req.NotAfter)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate template from CSR: %s", err.Error())
	}
	return csrBytes, certTemplate, nil
}

type CertificateSigner struct {
	Cert *x509.Certificate
	Key  interface{}
}

type CACertSpec struct {
	ValidFor time.Duration
	Crypto   CryptoAlgo
	Digest   DigestAlgo
	Parent   *CertificateSigner
	FullName pkix.Name
}

func CACertSpecFromCert(cert *x509.Certificate, validFor time.Duration, parent *CertificateSigner) (*CACertSpec, error) {
	cryptoAlgo, digestAlgo, err := decomposeSignatureAlgorithm(cert.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}
	return &CACertSpec{
		ValidFor: validFor,
		Crypto:   cryptoAlgo,
		Digest:   digestAlgo,
		Parent:   parent,
		FullName: cert.Subject,
	}, nil
}

func RenewCACertificate(cert *x509.Certificate, validFor time.Duration, parent *CertificateSigner) (*CertificateBytes, error) {
	spec, err := CACertSpecFromCert(cert, validFor, parent)
	if err != nil {
		return nil, err
	}
	return spec.Generate()
}

type CertificateBytes struct {
	CertBytes []byte
	KeyBytes  []byte
	CsrBytes  []byte
}

func (self *CACertSpec) Generate() (*CertificateBytes, error) {
	sigAlgo, err := Getx509SigAlgo(self.Crypto, self.Digest)
	if err != nil {
		return nil, err
	}

	pubkey, privkey, err := GenKeyPair(self.Crypto)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, maxSerial)
	if err != nil {
		return nil, err
	}
	keyBytes, err := MarshalPrivateKey(privkey)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	notBefore := now.Add(-10 * time.Minute).UTC()
	notAfter := now.Add(self.ValidFor).UTC()
	if self.Parent == nil {
		template := x509.Certificate{
			SignatureAlgorithm:    sigAlgo,
			PublicKey:             pubkey,
			SerialNumber:          serial,
			Subject:               self.FullName,
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              caCertKeyUsage,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            1,
		}
		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pubkey, privkey)
		if err != nil {
			return nil, err
		}
		return &CertificateBytes{
			CertBytes: derBytes,
			KeyBytes:  keyBytes,
			CsrBytes:  nil,
		}, nil
	} else {
		caParams := CACertificateParameters{
			MaxPathLen: 0,
		}
		if self.Parent == nil {
			caParams.MaxPathLen = 1
		}
		req := InternalCertificateRequest{
			SignatureAlgorithm: sigAlgo,
			PublicKey:          pubkey,
			PrivateKey:         privkey,
			Subject:            self.FullName,
			KeyUsage:           caCertKeyUsage,
			ExtKeyUsage:        nil,
			NotBefore:          notBefore,
			NotAfter:           notAfter,
			CAParams:           &caParams,
		}
		csrBytes, template, err := GenerateSignableCertififcate(&req)
		if err != nil {
			return nil, err
		}
		derBytes, err := x509.CreateCertificate(rand.Reader, template, self.Parent.Cert, pubkey, self.Parent.Key)
		if err != nil {
			return nil, err
		}
		return &CertificateBytes{
			CertBytes: derBytes,
			KeyBytes:  keyBytes,
			CsrBytes:  csrBytes,
		}, nil
	}
}

func certFromCsr(csr *x509.CertificateRequest, keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage, caParams *CACertificateParameters, notBefore time.Time, notAfter time.Time) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, maxSerial)
	if err != nil {
		return nil, err
	}
	maxPathLen := 0
	if caParams != nil {
		maxPathLen = caParams.MaxPathLen
	}
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		BasicConstraintsValid: true,
		IsCA:                  caParams != nil,
		MaxPathLen:            maxPathLen,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
	}, nil
}

// TODO: this is crap.  I should rethink the way algorithms are selected.
func decomposeSignatureAlgorithm(algo x509.SignatureAlgorithm) (CryptoAlgo, DigestAlgo, error) {
	switch algo {
	case x509.SHA256WithRSA:
		return CryptoAlgoRsa4096, DigestAlgoSha256, nil
	case x509.SHA384WithRSA:
		return CryptoAlgoRsa4096, DigestAlgoSha384, nil
	case x509.SHA512WithRSA:
		return CryptoAlgoRsa4096, DigestAlgoSha512, nil
	case x509.ECDSAWithSHA256:
		return CryptoAlgoEcdsaP256, DigestAlgoSha256, nil
	case x509.ECDSAWithSHA384:
		return CryptoAlgoEcdsaP256, DigestAlgoSha384, nil
	case x509.ECDSAWithSHA512:
		return CryptoAlgoEcdsaP256, DigestAlgoSha512, nil
	default:
		return 0, 0, fmt.Errorf("unsupported signature algorithm %v", algo)
	}
}

type KeyUsage int

const (
	KeyUsageServer KeyUsage = iota
	KeyUsageClient
)

type LeafCertSpec struct {
	ValidFor    time.Duration
	Crypto      CryptoAlgo
	Digest      DigestAlgo
	Parent      *CertificateSigner
	FullName    pkix.Name
	KeyUsage    KeyUsage
	IPAddresses []net.IP
	DNSNames    []string
}

func LeafCertSpecFromCert(cert *x509.Certificate, validFor time.Duration, parent *CertificateSigner) (*LeafCertSpec, error) {
	cryptoAlgo, digestAlgo, err := decomposeSignatureAlgorithm(cert.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}
	keyUsage := KeyUsageServer
	for _, extKeyUsage := range cert.ExtKeyUsage {
		if extKeyUsage == x509.ExtKeyUsageClientAuth {
			keyUsage = KeyUsageClient
		}
	}
	return &LeafCertSpec{
		ValidFor:    validFor,
		Crypto:      cryptoAlgo,
		Digest:      digestAlgo,
		Parent:      parent,
		FullName:    cert.Subject,
		KeyUsage:    keyUsage,
		IPAddresses: cert.IPAddresses,
		DNSNames:    cert.DNSNames,
	}, nil
}

func RenewLeafCertificate(cert *x509.Certificate, validFor time.Duration, parent *CertificateSigner) (*CertificateBytes, error) {
	spec, err := LeafCertSpecFromCert(cert, validFor, parent)
	if err != nil {
		return nil, err
	}
	return spec.Generate()
}

func (self *LeafCertSpec) Generate() (*CertificateBytes, error) {
	sigAlgo, err := Getx509SigAlgo(self.Crypto, self.Digest)
	if err != nil {
		return nil, err
	}

	pubkey, privkey, err := GenKeyPair(self.Crypto)
	if err != nil {
		return nil, err
	}

	keyBytes, err := MarshalPrivateKey(privkey)
	if err != nil {
		return nil, err
	}

	var extKeyUsage []x509.ExtKeyUsage
	switch self.KeyUsage {
	case KeyUsageServer:
		extKeyUsage = serverCertExtKeyUsage
	case KeyUsageClient:
		extKeyUsage = clientCertExtKeyUsage
	}
	now := time.Now()
	notBefore := now.Add(-10 * time.Minute).UTC()
	notAfter := now.Add(self.ValidFor).UTC()
	req := InternalCertificateRequest{
		SignatureAlgorithm: sigAlgo,
		PublicKey:          pubkey,
		PrivateKey:         privkey,
		Subject:            self.FullName,
		KeyUsage:           leafCertKeyUsage,
		ExtKeyUsage:        extKeyUsage,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		CAParams:           nil,
	}
	csrBytes, template, err := GenerateSignableCertififcate(&req)
	if err != nil {
		return nil, err
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, self.Parent.Cert, pubkey, self.Parent.Key)
	if err != nil {
		return nil, err
	}
	return &CertificateBytes{
		CertBytes: derBytes,
		CsrBytes:  csrBytes,
		KeyBytes:  keyBytes,
	}, nil
}
