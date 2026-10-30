package agent

import (
	"crypto/rand"
	"fmt"
)

func NewProcessInstanceID() (
	string,
	error,
) {
	raw :=
		make(
			[]byte,
			16,
		)

	if _, err :=
		rand.Read(raw); err != nil {

		return "",
			err
	}

	// RFC 4122 version 4 / variant 1.
	raw[6] =
		(raw[6] & 0x0f) |
			0x40

	raw[8] =
		(raw[8] & 0x3f) |
			0x80

	return fmt.Sprintf(
			"%x-%x-%x-%x-%x",
			raw[0:4],
			raw[4:6],
			raw[6:8],
			raw[8:10],
			raw[10:16],
		),
		nil
}
