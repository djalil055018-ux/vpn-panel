package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge/http01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"

	"vpn-platform/internal/core/xray"
	"vpn-platform/internal/model"
)

type certificateAccount struct {
	email        string
	registration *acme.ExtendedAccount
	key          crypto.Signer
}

func (a *certificateAccount) GetEmail() string {
	return a.email
}

func (a *certificateAccount) GetRegistration() *acme.ExtendedAccount {
	return a.registration
}

func (a *certificateAccount) GetPrivateKey() crypto.Signer {
	return a.key
}

func certificateCAURL(
	environment string,
) (
	string,
	error,
) {
	switch environment {
	case "staging":
		return lego.DirectoryURLLetsEncryptStaging,
			nil
	case "production":
		return lego.DirectoryURLLetsEncrypt,
			nil
	default:
		return "",
			fmt.Errorf(
				"unsupported ACME environment %q",
				environment,
			)
	}
}

func validCertificateID(
	value string,
) bool {
	if len(value) != 36 {
		return false
	}

	for index, ch := range value {
		switch index {
		case 8, 13, 18, 23:
			if ch != '-' {
				return false
			}
		default:
			if !(ch >= '0' &&
				ch <= '9' ||
				ch >= 'a' &&
					ch <= 'f' ||
				ch >= 'A' &&
					ch <= 'F') {
				return false
			}
		}
	}

	return true
}

func writeAtomicFile(
	path string,
	data []byte,
	mode os.FileMode,
) error {
	dir :=
		filepath.Dir(path)

	if err :=
		os.MkdirAll(
			dir,
			0700,
		); err != nil {
		return err
	}

	if err :=
		os.Chmod(
			dir,
			0700,
		); err != nil {
		return err
	}

	tmp, err :=
		os.CreateTemp(
			dir,
			".vpn-platform-tmp-*",
		)
	if err != nil {
		return err
	}

	tmpName :=
		tmp.Name()

	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(
			tmpName,
		)
	}

	if err :=
		tmp.Chmod(mode); err != nil {
		cleanup()
		return err
	}

	if _, err :=
		tmp.Write(data); err != nil {
		cleanup()
		return err
	}

	if err :=
		tmp.Sync(); err != nil {
		cleanup()
		return err
	}

	if err :=
		tmp.Close(); err != nil {
		_ = os.Remove(
			tmpName,
		)
		return err
	}

	if err :=
		os.Rename(
			tmpName,
			path,
		); err != nil {
		_ = os.Remove(
			tmpName,
		)
		return err
	}

	return os.Chmod(
		path,
		mode,
	)
}

func loadOrCreateACMEAccountKey(
	path string,
) (
	crypto.Signer,
	error,
) {
	raw, err :=
		os.ReadFile(path)

	if err == nil {
		block, _ :=
			pem.Decode(raw)

		if block == nil {
			return nil,
				errors.New(
					"invalid ACME account key PEM",
				)
		}

		parsed, err :=
			x509.ParsePKCS8PrivateKey(
				block.Bytes,
			)
		if err != nil {
			return nil, err
		}

		signer, ok :=
			parsed.(crypto.Signer)

		if !ok {
			return nil,
				errors.New(
					"ACME account key is not a signer",
				)
		}

		if err :=
			os.Chmod(
				path,
				0600,
			); err != nil {
			return nil, err
		}

		return signer, nil
	}

	if !errors.Is(
		err,
		os.ErrNotExist,
	) {
		return nil, err
	}

	key, err :=
		ecdsa.GenerateKey(
			elliptic.P256(),
			rand.Reader,
		)
	if err != nil {
		return nil, err
	}

	der, err :=
		x509.MarshalPKCS8PrivateKey(
			key,
		)
	if err != nil {
		return nil, err
	}

	pemValue :=
		pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: der,
			},
		)

	if len(pemValue) == 0 {
		return nil,
			errors.New(
				"failed to encode ACME account key",
			)
	}

	if err :=
		writeAtomicFile(
			path,
			pemValue,
			0600,
		); err != nil {
		return nil, err
	}

	return key, nil
}

func randomVersionSuffix() (
	string,
	error,
) {
	raw :=
		make(
			[]byte,
			6,
		)

	if _, err :=
		rand.Read(raw); err != nil {
		return "", err
	}

	return hex.EncodeToString(raw),
		nil
}

func firstCertificatePEM(
	bundle []byte,
) (
	[]byte,
	*x509.Certificate,
	error,
) {
	block, _ :=
		pem.Decode(bundle)

	if block == nil ||
		block.Type != "CERTIFICATE" {
		return nil,
			nil,
			errors.New(
				"certificate bundle has no leaf certificate",
			)
	}

	parsed, err :=
		x509.ParseCertificate(
			block.Bytes,
		)
	if err != nil {
		return nil,
			nil,
			err
	}

	leafPEM :=
		pem.EncodeToMemory(
			&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: block.Bytes,
			},
		)

	return leafPEM,
		parsed,
		nil
}

func installCertificateVersion(
	baseDir string,
	certificateID string,
	domain string,
	resource *certificate.Resource,
) (
	*x509.Certificate,
	error,
) {
	if !validCertificateID(
		certificateID,
	) {
		return nil,
			errors.New(
				"invalid certificate id",
			)
	}

	if resource == nil ||
		len(resource.Certificate) == 0 ||
		len(resource.PrivateKey) == 0 {
		return nil,
			errors.New(
				"ACME returned incomplete certificate material",
			)
	}
	// Validate the pair before creating a version or replacing the current link.
	if _, err := tls.X509KeyPair(resource.Certificate, resource.PrivateKey); err != nil {
		return nil, errors.New("certificate and private key do not form a valid pair")
	}

	leafPEM, leaf, err :=
		firstCertificatePEM(
			resource.Certificate,
		)
	if err != nil {
		return nil, err
	}
	if now := time.Now(); now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("certificate is outside its validity period")
	}

	if err :=
		leaf.VerifyHostname(
			domain,
		); err != nil {
		return nil,
			fmt.Errorf(
				"certificate hostname verification failed: %w",
				err,
			)
	}

	root :=
		filepath.Join(
			baseDir,
			"certificates",
			certificateID,
		)

	versionsDir :=
		filepath.Join(
			root,
			"versions",
		)

	if err :=
		os.MkdirAll(
			versionsDir,
			0700,
		); err != nil {
		return nil, err
	}

	if err :=
		os.Chmod(
			root,
			0700,
		); err != nil {
		return nil, err
	}

	if err :=
		os.Chmod(
			versionsDir,
			0700,
		); err != nil {
		return nil, err
	}

	suffix, err :=
		randomVersionSuffix()
	if err != nil {
		return nil, err
	}

	versionName :=
		time.Now().
			UTC().
			Format(
				"20060102T150405.000000000Z",
			) +
			"-" +
			suffix

	versionDir :=
		filepath.Join(
			versionsDir,
			versionName,
		)

	if err :=
		os.Mkdir(
			versionDir,
			0700,
		); err != nil {
		return nil, err
	}

	cleanupVersion := true

	defer func() {
		if cleanupVersion {
			_ = os.RemoveAll(
				versionDir,
			)
		}
	}()

	if err :=
		writeAtomicFile(
			filepath.Join(
				versionDir,
				"certificate.pem",
			),
			leafPEM,
			0644,
		); err != nil {
		return nil, err
	}

	if err :=
		writeAtomicFile(
			filepath.Join(
				versionDir,
				"fullchain.pem",
			),
			resource.Certificate,
			0644,
		); err != nil {
		return nil, err
	}

	if err :=
		writeAtomicFile(
			filepath.Join(
				versionDir,
				"private.key",
			),
			resource.PrivateKey,
			0600,
		); err != nil {
		return nil, err
	}

	linkTarget :=
		filepath.Join(
			"versions",
			versionName,
		)

	tempLink :=
		filepath.Join(
			root,
			".current-"+suffix,
		)

	if err :=
		os.Symlink(
			linkTarget,
			tempLink,
		); err != nil {
		return nil, err
	}

	if err :=
		os.Rename(
			tempLink,
			filepath.Join(
				root,
				"current",
			),
		); err != nil {
		_ = os.Remove(
			tempLink,
		)
		return nil, err
	}

	cleanupVersion =
		false

	return leaf, nil
}

// Legacy callers retain the Xray behavior. The running worker always receives
// its active driver's explicit refresher and never selects a core here.
func obtainCertificate(ctx context.Context, baseDir string, grant model.CertificateJobGrant) (model.CertificateJobResult, error) {
	return obtainCertificateWithRuntime(ctx, baseDir, grant, xrayCertificateRefresher(xray.New(baseDir)))
}

func obtainCertificateWithRuntime(
	ctx context.Context,
	baseDir string,
	grant model.CertificateJobGrant,
	refresh certificateRuntimeRefresher,
) (
	model.CertificateJobResult,
	error,
) {
	if ctx.Err() != nil {
		return model.CertificateJobResult{}, ctx.Err()
	}
	if !validCertificateID(grant.CertificateID) {
		return model.CertificateJobResult{}, errors.New("invalid certificate id")
	}
	expectedRef := "certificates/" + grant.CertificateID
	if grant.CertificateRef != expectedRef {
		return model.CertificateJobResult{}, errors.New("certificate_ref does not match certificate id")
	}
	if grant.Operation == "delete" {
		if err := removeCertificateMaterial(baseDir, grant.CertificateID); err != nil {
			return model.CertificateJobResult{}, fmt.Errorf("remove certificate material: %w", err)
		}
		return model.CertificateJobResult{JobID: grant.JobID, CertificateID: grant.CertificateID, LeaseToken: grant.LeaseToken, Success: true}, nil
	}
	if grant.Operation != "issue" && grant.Operation != "renew" {
		return model.CertificateJobResult{}, errors.New("invalid certificate operation")
	}
	if refresh == nil {
		return model.CertificateJobResult{}, errCertificateRuntime
	}
	if grant.Provider !=
		"letsencrypt" {
		return model.CertificateJobResult{},
			fmt.Errorf(
				"unsupported certificate provider %q",
				grant.Provider,
			)
	}

	if grant.ChallengeType !=
		"http-01" {
		return model.CertificateJobResult{},
			fmt.Errorf(
				"unsupported challenge type %q",
				grant.ChallengeType,
			)
	}

	caURL, err :=
		certificateCAURL(
			grant.Environment,
		)
	if err != nil {
		return model.CertificateJobResult{},
			err
	}

	accountDir :=
		filepath.Join(
			baseDir,
			"acme",
			"letsencrypt-"+
				grant.Environment,
		)

	if err :=
		os.MkdirAll(
			accountDir,
			0700,
		); err != nil {
		return model.CertificateJobResult{},
			err
	}

	if err :=
		os.Chmod(
			accountDir,
			0700,
		); err != nil {
		return model.CertificateJobResult{},
			err
	}

	accountKey, err :=
		loadOrCreateACMEAccountKey(
			filepath.Join(
				accountDir,
				"account.key",
			),
		)
	if err != nil {
		return model.CertificateJobResult{},
			fmt.Errorf(
				"ACME account key: %w",
				err,
			)
	}

	email := ""

	if grant.ContactEmail != nil {
		email =
			strings.TrimSpace(
				*grant.ContactEmail,
			)
	}

	account :=
		&certificateAccount{
			email: email,
			key:   accountKey,
		}

	config :=
		lego.NewConfig(
			account,
		)

	config.CADirURL =
		caURL

	config.Certificate.Timeout =
		10 * time.Minute

	client, err :=
		lego.NewClient(
			config,
		)
	if err != nil {
		return model.CertificateJobResult{},
			fmt.Errorf(
				"create ACME client: %w",
				err,
			)
	}

	if err :=
		client.Challenge.SetHTTP01Provider(
			http01.NewProviderServer(
				"",
				"80",
			),
		); err != nil {
		return model.CertificateJobResult{},
			fmt.Errorf(
				"configure HTTP-01: %w",
				err,
			)
	}

	reg, err :=
		client.Registration.Register(
			ctx,
			registration.RegisterOptions{
				TermsOfServiceAgreed: true,
			},
		)
	if err != nil {
		return model.CertificateJobResult{},
			fmt.Errorf(
				"ACME registration: %w",
				err,
			)
	}

	account.registration =
		reg

	resource, err :=
		client.Certificate.Obtain(
			ctx,
			certificate.ObtainRequest{
				Domains: []string{
					grant.Domain,
				},
				KeyType: certcrypto.RSA2048,
				Bundle:  true,
			},
		)
	if err != nil {
		return model.CertificateJobResult{},
			fmt.Errorf(
				"ACME obtain: %w",
				err,
			)
	}

	if err := ctx.Err(); err != nil {
		return model.CertificateJobResult{}, err
	}
	leaf, err :=
		installCertificateVersion(
			baseDir,
			grant.CertificateID,
			grant.Domain,
			resource,
		)
	if err != nil {
		return model.CertificateJobResult{},
			fmt.Errorf(
				"install certificate: %w",
				err,
			)
	}

	if err := refreshCertificateRuntime(ctx, refresh, grant.CertificateID, grant.Domain); err != nil {
		return model.CertificateJobResult{}, fmt.Errorf("refresh TLS runtime certificate: %w", err)
	}

	sum :=
		sha256.Sum256(
			leaf.Raw,
		)

	notBefore :=
		leaf.NotBefore.UTC()

	notAfter :=
		leaf.NotAfter.UTC()

	return model.CertificateJobResult{
		JobID:         grant.JobID,
		CertificateID: grant.CertificateID,
		LeaseToken:    grant.LeaseToken,
		Success:       true,
		Issuer:        leaf.Issuer.String(),
		FingerprintSHA256: hex.EncodeToString(
			sum[:],
		),
		NotBefore: &notBefore,
		NotAfter:  &notAfter,
	}, nil
}

func removeCertificateMaterial(baseDir, certificateID string) error {
	if !validCertificateID(certificateID) || baseDir == "" {
		return errors.New("invalid certificate removal target")
	}
	certificatesDir := filepath.Join(baseDir, "certificates")
	info, err := os.Lstat(certificatesDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("certificate directory is not a safe directory")
	}
	root, err := os.OpenRoot(certificatesDir)
	if err != nil {
		return err
	}
	defer root.Close()
	target, err := root.Lstat(certificateID)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if target.Mode()&os.ModeSymlink != 0 || !target.IsDir() {
		return errors.New("certificate material path is not a directory")
	}
	return root.RemoveAll(certificateID)
}
