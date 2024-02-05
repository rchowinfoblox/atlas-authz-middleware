package grpc_opa_middleware

import (
	"context"
	"fmt"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	logrus "github.com/sirupsen/logrus"
)

const (
	// DefaultEffectivePermissionsApiPath is default OPA path to fetch effective permissions
	DefaultEffectivePermissionsApiPath = "v1/data/authz/rbac/effective_permissions_api"
)

// EffectivePermissionsApiInput is the input payload for effective_permissions_api
type EffectivePermissionsApiInput struct {
	JWT string `json:"jwt"`
}

// EffectivePermissionRec defines an effective-permission
type EffectivePermissionRec struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Hidden           bool     `json:"hidden"`
	EntitledFeatures []string `json:"entitled_features"`
}

// EffectivePermissionsType defines the results type returned by GetEffectivePermissions()
// (map of effective-permission-id to EffectivePermissionRec)
type EffectivePermissionsType map[string]EffectivePermissionRec

// EffectivePermissionsApiResult is the data type json.Unmarshaled from OPA RESTAPI query to effective_permissions_api
type EffectivePermissionsApiResult struct {
	Result *EffectivePermissionsType `json:"result"`
}

// GetEffectivePermissionsBytes queries account entitled features data
// for the specified account-ids and entitled-services.
// If both account-ids and entitled-services are empty,
// then data for all entitled-services in all accounts are returned.
// Returns the raw JSON string response
func (a *DefaultAuthorizer) GetEffectivePermissionsBytes(ctx context.Context) ([]byte, error) {
	lgNtry := ctxlogrus.Extract(ctx)

	rawJWT, err := a.ExtractJWT(ctx)
	if err != nil {
		lgNtry.WithError(err).Error("extract_jwt_fail")
		return nil, err
	}

	opaReq := OPARequest{
		Input: &EffectivePermissionsApiInput{
			JWT: rawJWT,
		},
	}

	rawBytes, err := a.clienter.CustomQueryBytes(ctx, a.effectivePermissionsApi, opaReq)
	if err != nil {
		lgNtry.WithError(err).Error("get_effective_permissions_raw_fail")
		return nil, err
	}

	lgNtry.WithFields(logrus.Fields{
		"rawBytes": string(rawBytes),
	}).Trace("get_effective_permissions_raw_okay")

	return rawBytes, nil
}

// GetEffectivePermissions queries account entitled features data
// for the specified account-ids and entitled-services.
// If both account-ids and entitled-services are empty,
// then data for all entitled-services in all accounts are returned.
func (a *DefaultAuthorizer) GetEffectivePermissions(ctx context.Context) (*EffectivePermissionsType, error) {
	lgNtry := ctxlogrus.Extract(ctx)

	rawJWT, err := a.ExtractJWT(ctx)
	if err != nil {
		lgNtry.WithError(err).Error("extract_jwt_fail")
		return nil, err
	}

	opaReq := OPARequest{
		Input: &EffectivePermissionsApiInput{
			JWT: rawJWT,
		},
	}

	permResult := EffectivePermissionsApiResult{}
	err = a.clienter.CustomQuery(ctx, a.effectivePermissionsApi, opaReq, &permResult)
	if err != nil {
		lgNtry.WithError(err).Error("get_effective_permissions_fail")
		return nil, err
	}

	lgNtry.WithFields(logrus.Fields{
		"permResult": fmt.Sprintf("%#v", permResult),
	}).Trace("get_effective_permissions_okay")

	return permResult.Result, nil
}
