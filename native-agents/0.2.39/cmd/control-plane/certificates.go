package main

import (
	"errors"
	"net"
	"net/http"
	"net/mail"
	"strings"

	"vpn-platform/internal/store"
)

func normalizeCertificateDomain(
	value string,
) string {
	return strings.TrimSuffix(
		strings.ToLower(
			strings.TrimSpace(value),
		),
		".",
	)
}

func validDNSLabel(
	label string,
) bool {
	if label == "" ||
		len(label) > 63 {
		return false
	}

	if strings.HasPrefix(
		label,
		"-",
	) ||
		strings.HasSuffix(
			label,
			"-",
		) {
		return false
	}

	for _, ch := range label {
		isLetter :=
			ch >= 'a' &&
				ch <= 'z'

		isDigit :=
			ch >= '0' &&
				ch <= '9'

		isHyphen :=
			ch == '-'

		if !isLetter &&
			!isDigit &&
			!isHyphen {
			return false
		}
	}

	return true
}

func validCertificateDomain(
	value string,
) bool {
	if value == "" ||
		len(value) > 253 {
		return false
	}

	if net.ParseIP(value) != nil {
		return false
	}

	labels :=
		strings.Split(
			value,
			".",
		)

	if len(labels) < 2 {
		return false
	}

	for _, label := range labels {
		if !validDNSLabel(
			label,
		) {
			return false
		}
	}

	return true
}

func (a *application) createNodeCertificate(
	w http.ResponseWriter,
	r *http.Request,
) {
	nodeID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	if nodeID == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"node id is required",
		)
		return
	}

	var input struct {
		Domain        string  `json:"domain"`
		Provider      string  `json:"provider"`
		ChallengeType string  `json:"challenge_type"`
		Environment   string  `json:"environment"`
		ContactEmail  *string `json:"contact_email"`
		AutoRenew     *bool   `json:"auto_renew"`
	}

	if err :=
		readJSON(
			r,
			&input,
		); err != nil {
		writeError(
			w,
			http.StatusBadRequest,
			err.Error(),
		)
		return
	}

	input.Domain =
		normalizeCertificateDomain(
			input.Domain,
		)

	input.Provider =
		strings.ToLower(
			strings.TrimSpace(
				input.Provider,
			),
		)

	input.ChallengeType =
		strings.ToLower(
			strings.TrimSpace(
				input.ChallengeType,
			),
		)

	input.Environment =
		strings.ToLower(
			strings.TrimSpace(
				input.Environment,
			),
		)

	if !validCertificateDomain(
		input.Domain,
	) {
		writeError(
			w,
			http.StatusBadRequest,
			"invalid certificate domain",
		)
		return
	}

	if input.Provider == "" {
		input.Provider =
			"letsencrypt"
	}

	if input.Provider !=
		"letsencrypt" {
		writeError(
			w,
			http.StatusBadRequest,
			"unsupported certificate provider",
		)
		return
	}

	if input.ChallengeType == "" {
		input.ChallengeType =
			"http-01"
	}

	if input.ChallengeType !=
		"http-01" {
		writeError(
			w,
			http.StatusBadRequest,
			"unsupported ACME challenge type",
		)
		return
	}

	if input.Environment == "" {
		input.Environment =
			"staging"
	}

	if input.Environment != "staging" &&
		input.Environment != "production" {
		writeError(
			w,
			http.StatusBadRequest,
			"environment must be staging or production",
		)
		return
	}

	if input.ContactEmail != nil {
		value :=
			strings.TrimSpace(
				*input.ContactEmail,
			)

		if value == "" {
			input.ContactEmail =
				nil
		} else {
			address, err :=
				mail.ParseAddress(
					value,
				)

			if err != nil ||
				address.Address != value {
				writeError(
					w,
					http.StatusBadRequest,
					"invalid contact email",
				)
				return
			}

			input.ContactEmail =
				&value
		}
	}

	autoRenew := true

	if input.AutoRenew != nil {
		autoRenew =
			*input.AutoRenew
	}

	certificate, err :=
		a.store.CreateNodeCertificate(
			r.Context(),
			nodeID,
			input.Domain,
			input.Provider,
			input.ChallengeType,
			input.Environment,
			input.ContactEmail,
			autoRenew,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"node not found",
		)
		return

	case errors.Is(
		err,
		store.ErrNodeCertificateExists,
	):
		writeError(
			w,
			http.StatusConflict,
			"certificate for this domain already exists on node",
		)
		return

	case err != nil:
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusCreated,
		certificate,
	)
}

func (a *application) listNodeCertificates(
	w http.ResponseWriter,
	r *http.Request,
) {
	nodeID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	certificates, err :=
		a.store.ListNodeCertificates(
			r.Context(),
			nodeID,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"node not found",
		)
		return

	case err != nil:
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"certificates": certificates,
		},
	)
}

func (a *application) getNodeCertificate(
	w http.ResponseWriter,
	r *http.Request,
) {
	certificateID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	certificate, err :=
		a.store.GetNodeCertificate(
			r.Context(),
			certificateID,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"certificate not found",
		)
		return

	case err != nil:
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		certificate,
	)
}
