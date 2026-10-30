package store

import (
	"strconv"
	"strings"
)

const HysteriaOperationalMinimumAgent = "0.2.25"

func HysteriaAgentOperationallyCompatible(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}

	var actual [3]uint64

	for index, part := range parts {
		number, err := strconv.ParseUint(part, 10, 32)
		if err != nil || strconv.FormatUint(number, 10) != part {
			return false
		}
		actual[index] = number
	}

	minimum := [3]uint64{0, 2, 25}

	for index := range actual {
		if actual[index] != minimum[index] {
			return actual[index] > minimum[index]
		}
	}

	return true
}
