package config

import (
	"errors"
	"fmt"
)

const defaultListenAddr = ":8080"

const (
	envListenAddr     = "SERVER_ADDR"
	envIssuerID       = "INTERNAL_JWT_ISSUER"
	envSigningKeyFile = "INTERNAL_JWT_SIGNING_KEY_FILE"
)

type Config struct {
	ListenAddr     string
	IssuerID       string
	SigningKeyFile string
}

func Load(getenv func(string) string) (Config, error) {
	listenAddr := getenv(envListenAddr)
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}

	issuerID := getenv(envIssuerID)
	signingKeyFile := getenv(envSigningKeyFile)

	var errs []error

	if issuerID == "" {
		errs = append(errs, missingEnvError(envIssuerID))
	}

	if signingKeyFile == "" {
		errs = append(errs, missingEnvError(envSigningKeyFile))
	}

	if err := errors.Join(errs...); err != nil {
		var zero Config

		return zero, err
	}

	return Config{
		ListenAddr:     listenAddr,
		IssuerID:       issuerID,
		SigningKeyFile: signingKeyFile,
	}, nil
}

func missingEnvError(key string) error {
	return fmt.Errorf("%s is required but not set", key)
}
