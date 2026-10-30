package xray

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"vpn-platform/internal/model"
)

var realityServiceIDPattern = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`,
)

func (d *Driver) realitySecretsDir() string {
	return filepath.Join(
		d.BaseDir,
		"secrets",
		"reality",
	)
}

func validateRealitySecretRef(
	service model.ServiceSpec,
) error {
	if !realityServiceIDPattern.MatchString(
		service.ID,
	) {
		return fmt.Errorf(
			"invalid reality service id",
		)
	}

	if service.Reality == nil {
		return fmt.Errorf(
			"reality settings are required for service %s",
			service.ID,
		)
	}

	expected :=
		"reality/" + service.ID

	if service.Reality.SecretRef != expected {
		return fmt.Errorf(
			"invalid reality secret_ref for service %s",
			service.ID,
		)
	}

	return nil
}

func decodeRealityPrivateKey(
	raw string,
) (
	*ecdh.PrivateKey,
	error,
) {
	decoded, err :=
		base64.RawURLEncoding.DecodeString(
			strings.TrimSpace(raw),
		)

	if err != nil {
		return nil, fmt.Errorf(
			"decode reality private key: %w",
			err,
		)
	}

	key, err :=
		ecdh.X25519().NewPrivateKey(
			decoded,
		)

	if err != nil {
		return nil, fmt.Errorf(
			"parse reality private key: %w",
			err,
		)
	}

	return key, nil
}

func encodeRealityPrivateKey(
	key *ecdh.PrivateKey,
) string {
	return base64.RawURLEncoding.
		EncodeToString(
			key.Bytes(),
		)
}

func encodeRealityPublicKey(
	key *ecdh.PublicKey,
) string {
	return base64.RawURLEncoding.
		EncodeToString(
			key.Bytes(),
		)
}

func writeRealityPrivateKeyAtomic(
	path string,
	value string,
) error {
	tmp :=
		fmt.Sprintf(
			"%s.tmp-%d",
			path,
			os.Getpid(),
		)

	file, err :=
		os.OpenFile(
			tmp,
			os.O_WRONLY|
				os.O_CREATE|
				os.O_EXCL,
			0600,
		)

	if err != nil {
		return err
	}

	cleanup := true

	defer func() {
		if cleanup {
			_ = os.Remove(tmp)
		}
	}()

	if _, err :=
		file.WriteString(value + "\n"); err != nil {

		_ = file.Close()
		return err
	}

	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}

	if err := file.Close(); err != nil {
		return err
	}

	if err :=
		os.Rename(
			tmp,
			path,
		); err != nil {

		return err
	}

	cleanup = false

	return os.Chmod(
		path,
		0600,
	)
}

func (d *Driver) ensureRealitySecret(
	service model.ServiceSpec,
) (
	privateKey string,
	publicKey string,
	err error,
) {
	if err :=
		validateRealitySecretRef(
			service,
		); err != nil {

		return "", "", err
	}

	dir := d.realitySecretsDir()

	if err :=
		os.MkdirAll(
			dir,
			0700,
		); err != nil {

		return "", "", err
	}

	if err :=
		os.Chmod(
			dir,
			0700,
		); err != nil {

		return "", "", err
	}

	path :=
		filepath.Join(
			dir,
			service.ID+".key",
		)

	raw, err :=
		os.ReadFile(path)

	switch {
	case err == nil:
		key, err :=
			decodeRealityPrivateKey(
				string(raw),
			)

		if err != nil {
			return "", "", err
		}

		if err :=
			os.Chmod(
				path,
				0600,
			); err != nil {

			return "", "", err
		}

		return encodeRealityPrivateKey(key),
			encodeRealityPublicKey(
				key.PublicKey(),
			),
			nil

	case !errors.Is(
		err,
		os.ErrNotExist,
	):
		return "", "", err
	}

	key, err :=
		ecdh.X25519().
			GenerateKey(
				rand.Reader,
			)

	if err != nil {
		return "", "", fmt.Errorf(
			"generate reality X25519 key: %w",
			err,
		)
	}

	privateKey =
		encodeRealityPrivateKey(key)

	publicKey =
		encodeRealityPublicKey(
			key.PublicKey(),
		)

	if err :=
		writeRealityPrivateKeyAtomic(
			path,
			privateKey,
		); err != nil {

		// Another execution may have won an atomic race.
		if existing, readErr :=
			os.ReadFile(path); readErr == nil {

			existingKey, parseErr :=
				decodeRealityPrivateKey(
					string(existing),
				)

			if parseErr != nil {
				return "", "", parseErr
			}

			return encodeRealityPrivateKey(
					existingKey,
				),
				encodeRealityPublicKey(
					existingKey.PublicKey(),
				),
				nil
		}

		return "", "", err
	}

	return privateKey,
		publicKey,
		nil
}

func (d *Driver) resolveRealitySecrets(
	state model.DesiredState,
) (
	model.DesiredState,
	[]model.RealityPublicMaterial,
	error,
) {
	state.Services =
		append(
			[]model.ServiceSpec(nil),
			state.Services...,
		)

	materials :=
		make(
			[]model.RealityPublicMaterial,
			0,
		)

	for i := range state.Services {

		service :=
			&state.Services[i]

		if service.Security !=
			"reality" {

			continue
		}

		if service.Reality == nil {
			return state,
				nil,
				fmt.Errorf(
					"reality settings are required for service %s",
					service.ID,
				)
		}

		privateKey,
			publicKey,
			err :=
			d.profileRealitySecret(
				*service,
				state.XrayProfile,
			)

		if err != nil {
			return state,
				nil,
				err
		}

		realityCopy :=
			*service.Reality

		realityCopy.PrivateKey =
			privateKey

		service.Reality =
			&realityCopy

		materials =
			append(
				materials,
				model.RealityPublicMaterial{
					ServiceID: service.ID,
					PublicKey: publicKey,
				},
			)
	}

	return state,
		materials,
		nil
}

func (d *Driver) RealityPublicMaterials(
	state model.DesiredState,
) (
	[]model.RealityPublicMaterial,
	error,
) {
	materials :=
		make(
			[]model.RealityPublicMaterial,
			0,
		)

	for _, service := range state.Services {

		if service.Security !=
			"reality" {

			continue
		}

		_,
			publicKey,
			err :=
			d.profileRealitySecret(
				service,
				state.XrayProfile,
			)

		if err != nil {
			return nil, err
		}

		materials =
			append(
				materials,
				model.RealityPublicMaterial{
					ServiceID: service.ID,

					PublicKey: publicKey,
				},
			)
	}

	return materials, nil
}
