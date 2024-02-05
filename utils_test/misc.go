package utils_test

import (
	"context"
	"time"

	"google.golang.org/grpc/metadata"

	atlas_claims "github.com/infobloxopen/atlas-claims"
)

type TestingTContextKeyType string
const TestingTContextKey = TestingTContextKeyType("*testing.T")

type TestCaseIndexContextKeyType string
const TestCaseIndexContextKey = TestCaseIndexContextKeyType("TestCaseIndex")

type TestCaseNameContextKeyType string
const TestCaseNameContextKey = TestCaseNameContextKeyType("TestCaseName")

// BuildJWT returns a new JWT using specified claims and hardcoded duration and HMAC-key
func BuildJWT(claims atlas_claims.Claims) (jwt string, err error) {
	jwtHmacKey := "fake-hmac-key-for-testing"
	jwtDuration := time.Hour * 24 * 365 * 100
	jwt, err = atlas_claims.BuildJwt(&claims, jwtHmacKey, jwtDuration)
	return
}

// NewContextWithJWT returns a new Context with specified JWT injected into it
func NewContextWithJWT(ctx context.Context, jwt string) (newCtx context.Context) {
	newCtx = metadata.NewIncomingContext(ctx,
		metadata.New(map[string]string{"Authorization": "Bearer " + jwt}))
	return
}

// NewContextWithClaims returns a new Context with a new JWT using the specified claims
func NewContextWithClaims(ctx context.Context, claims atlas_claims.Claims) (newCtx context.Context, jwt string, err error) {
	newCtx = ctx
	jwt, err = BuildJWT(claims)
	if err == nil {
		newCtx = NewContextWithJWT(ctx, jwt)
	}
	return
}
