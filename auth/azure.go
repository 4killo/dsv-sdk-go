package auth

import (
	"errors"
	"net/http"

	"github.com/Azure/go-autorest/autorest"
	azure "github.com/Azure/go-autorest/autorest/azure/auth"
)

const (
	resource = "https://management.azure.com/"
)

func (a *authorization) GetBearerToken() (string, error) {

	authorizer, err := azure.NewAuthorizerFromEnvironmentWithResource(resource)
	if err != nil {
		return "", errors.New("failed to create azure authorizer")
	}
	r := http.Request{}
	p := authorizer.WithAuthorization()
	req, err := autorest.CreatePreparer(p).Prepare(&r)
	if err != nil {
		return "", errors.New("failed to generate azure auth token" + err.Error())
	}

	qualifiedBearer := req.Header.Get("Authorization")
	lenPrefix := len("Bearer ")
	if len(qualifiedBearer) < lenPrefix {
		return "", errors.New("received invalid bearer token")
	}

	return qualifiedBearer[lenPrefix:], nil

}
