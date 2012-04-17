package jwt

import (
	"fmt"
	"errors"
)

var signingMethods = map[string]func() SigningMethod{}

// Signing method
type SigningMethod interface {
}

func RegisterSigningMethod(alg string, f func() SigningMethod) {
	signingMethods[alg] = f
}

func GetSigningMethod(alg string)(method SigningMethod, err error) {
	if methodF, ok := signingMethods[alg]; ok {
		method = methodF()
	} else {
		err = errors.New(fmt.Sprintf("Invalid signing method (alg): %v", method))
	}
	return
}