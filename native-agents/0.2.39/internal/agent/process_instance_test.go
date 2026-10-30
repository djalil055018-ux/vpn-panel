package agent

import (
	"regexp"
	"testing"
)

func TestNewProcessInstanceID(
	t *testing.T,
) {
	first, err :=
		NewProcessInstanceID()

	if err != nil {
		t.Fatal(err)
	}

	second, err :=
		NewProcessInstanceID()

	if err != nil {
		t.Fatal(err)
	}

	if first == second {
		t.Fatal(
			"process instance IDs unexpectedly equal",
		)
	}

	valid :=
		regexp.MustCompile(
			`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
		)

	if !valid.MatchString(first) {
		t.Fatalf(
			"invalid process instance UUID: %q",
			first,
		)
	}
}
