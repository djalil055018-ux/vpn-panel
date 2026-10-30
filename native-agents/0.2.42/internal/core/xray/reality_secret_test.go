package xray

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpn-platform/internal/model"
)

const testRealityServiceID = "11111111-1111-4111-8111-111111111111"

func testRealityService() model.ServiceSpec {
	return model.ServiceSpec{
		ID:        testRealityServiceID,
		Protocol:  "vless",
		Listen:    "0.0.0.0",
		Port:      443,
		Transport: "tcp",
		Security:  "reality",

		Reality: &model.RealitySpec{
			Destination: "www.microsoft.com:443",
			ServerName:  "www.microsoft.com",
			Fingerprint: "chrome",
			ShortID:     "0123456789abcdef",
			SecretRef: "reality/" +
				testRealityServiceID,
		},
	}
}

func TestRealitySecretStableAndPrivate(
	t *testing.T,
) {
	driver :=
		New(
			t.TempDir(),
		)

	service :=
		testRealityService()

	private1,
		public1,
		err :=
		driver.ensureRealitySecret(
			service,
		)

	if err != nil {
		t.Fatal(err)
	}

	private2,
		public2,
		err :=
		driver.ensureRealitySecret(
			service,
		)

	if err != nil {
		t.Fatal(err)
	}

	if private1 == "" ||
		public1 == "" {

		t.Fatal(
			"empty reality material",
		)
	}

	if private1 != private2 {
		t.Fatal(
			"private key changed",
		)
	}

	if public1 != public2 {
		t.Fatal(
			"public key changed",
		)
	}

	path :=
		filepath.Join(
			driver.realitySecretsDir(),
			testRealityServiceID+".key",
		)

	info, err :=
		os.Stat(path)

	if err != nil {
		t.Fatal(err)
	}

	if info.Mode().Perm() != 0600 {
		t.Fatalf(
			"key mode=%o want=600",
			info.Mode().Perm(),
		)
	}
}

func TestRealityPrivateKeyNotSerialized(
	t *testing.T,
) {
	state :=
		model.DesiredState{
			Services: []model.ServiceSpec{
				testRealityService(),
			},
		}

	state.Services[0].
		Reality.
		PrivateKey =
		"must-never-be-serialized"

	raw, err :=
		json.Marshal(state)

	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(
		string(raw),
		"must-never-be-serialized",
	) {
		t.Fatal(
			"reality private key leaked into JSON",
		)
	}

	if strings.Contains(
		string(raw),
		"private_key",
	) {
		t.Fatal(
			"private_key field leaked into JSON",
		)
	}
}

func TestRealitySecretRefIsPinnedToService(
	t *testing.T,
) {
	driver :=
		New(
			t.TempDir(),
		)

	service :=
		testRealityService()

	service.Reality.SecretRef =
		"reality/22222222-2222-4222-8222-222222222222"

	_, _, err :=
		driver.ensureRealitySecret(
			service,
		)

	if err == nil {
		t.Fatal(
			"expected invalid secret_ref error",
		)
	}
}
