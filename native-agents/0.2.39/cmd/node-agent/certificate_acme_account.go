package main

import (
	"crypto"

	"github.com/go-acme/lego/v5/acme"
)

type certificateACMEAccount struct {
	email        string
	registration *acme.ExtendedAccount
	privateKey   crypto.Signer
}

func (a *certificateACMEAccount) GetEmail() string {
	return a.email
}

func (a *certificateACMEAccount) GetRegistration() *acme.ExtendedAccount {
	return a.registration
}

func (a *certificateACMEAccount) GetPrivateKey() crypto.Signer {
	return a.privateKey
}
