package grpc_opa_middleware

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/infobloxopen/atlas-authz-middleware/pkg/opa_client"
	"github.com/infobloxopen/atlas-authz-middleware/utils_test"
	atlas_claims "github.com/infobloxopen/atlas-claims"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	logrus "github.com/sirupsen/logrus"
)

func TestGetEffectivePermissionsOpa(t *testing.T) {
	stdLoggr := logrus.StandardLogger()
	ctx, cancel := context.WithCancel(context.Background())
	ctx = context.WithValue(ctx, utils_test.TestingTContextKey, t)
	ctx = ctxlogrus.ToContext(ctx, logrus.NewEntry(stdLoggr))

	claims := atlas_claims.Claims{
		AccountId: "2001016",
	}
	ctx, _, err := utils_test.NewContextWithClaims(ctx, claims)
	if err != nil {
		t.Fatalf("NewContextWithClaims err: %s", err)
	}

	done := make(chan struct{})
	clienter := utils_test.StartOpa(ctx, t, done)
	cli, ok := clienter.(*opa_client.Client)
	if !ok {
		t.Fatal("Unable to convert interface to (*Client)")
		return
	}

	// Errors above here will leak containers
	defer func() {
		cancel()
		// Wait for container to be shutdown
		<-done
	}()

	policyRego, err := ioutil.ReadFile("testdata/mock_authz_policy.rego")
	if err != nil {
		t.Fatalf("ReadFile fatal err: %#v", err)
		return
	}

	var resp interface{}
	err = cli.UploadRegoPolicy(ctx, "mock_authz_policyid", policyRego, resp)
	if err != nil {
		t.Fatalf("OpaUploadPolicy fatal err: %#v", err)
		return
	}

	auther := NewDefaultAuthorizer("bogus_unused_application_value",
		WithOpaClienter(cli),
	)

	rawBytes, err := auther.GetEffectivePermissionsBytes(ctx)
	if err != nil {
		t.Errorf("FAIL: GetEffectivePermissionsBytes() unexpected err=%v", err)
	}
	t.Logf("rawBytes=%s", string(rawBytes))

	expectJson := `{"result":{"tag-list":{"entitled_features":["license.se"],"hidden":false,"id":"tag-list","name":"Tag List"},"tag-read":{"entitled_features":["license.se","license.td"],"hidden":true,"id":"tag-read","name":"Tag Read"},"user-manage":{"entitled_features":[],"hidden":true,"id":"user-manage","name":"User Manage"},"user-view":{"entitled_features":null,"hidden":false,"id":"user-view","name":"User View"}}}`

	if string(rawBytes) != expectJson {
		t.Errorf("FAIL:\nrawBytes:  %s\nexpectJson: %s", string(rawBytes), expectJson)
	}

	var actualAcctResult EffectivePermissionsApiResult
	err = json.Unmarshal(rawBytes, &actualAcctResult)
	t.Logf("actualAcctResult.Result=%#v", actualAcctResult.Result)

	expectAcctResult := EffectivePermissionsApiResult{
		Result: &EffectivePermissionsType{
			"user-view": {
				ID:               "user-view",
				Name:             "User View",
				Hidden:           false,
				EntitledFeatures: nil,
			},
			"user-manage": {
				ID:               "user-manage",
				Name:             "User Manage",
				Hidden:           true,
				EntitledFeatures: []string{},
			},
			"tag-list": {
				ID:               "tag-list",
				Name:             "Tag List",
				Hidden:           false,
				EntitledFeatures: []string{"license.se"},
			},
			"tag-read": {
				ID:               "tag-read",
				Name:             "Tag Read",
				Hidden:           true,
				EntitledFeatures: []string{"license.se", "license.td"},
			},
		},
	}
	if !reflect.DeepEqual(actualAcctResult.Result, expectAcctResult.Result) {
		t.Errorf("FAIL:\nactualAcctResult.Result:  %#v\nexpectAcctResult.Result: %#v",
			actualAcctResult.Result, expectAcctResult.Result)
	}

	var actualOpaResp OPAResponse
	err = json.Unmarshal(rawBytes, &actualOpaResp)
	t.Logf("actualOpaResp=%#v", actualOpaResp)

	expectOpaResp := OPAResponse{
		"result": map[string]interface{}{
			"user-view": map[string]interface{}{
				"id":                "user-view",
				"name":              "User View",
				"hidden":            false,
				"entitled_features": interface{}(nil),
			},
			"user-manage": map[string]interface{}{
				"id":                "user-manage",
				"name":              "User Manage",
				"hidden":            true,
				"entitled_features": []interface{}{},
			},
			"tag-list": map[string]interface{}{
				"id":                "tag-list",
				"name":              "Tag List",
				"hidden":            false,
				"entitled_features": []interface{}{"license.se"},
			},
			"tag-read": map[string]interface{}{
				"id":                "tag-read",
				"name":              "Tag Read",
				"hidden":            true,
				"entitled_features": []interface{}{"license.se", "license.td"},
			},
		},
	}
	if !reflect.DeepEqual(actualOpaResp, expectOpaResp) {
		t.Errorf("FAIL:\nactualOpaResp:  %#v\nexpectOpaResp: %#v", actualOpaResp, expectOpaResp)
	}
}

func TestGetEffectivePermissionsMockOpaClient(t *testing.T) {
	testMap := []struct {
		name         string
		regoRespJSON string
		expectErr    bool
		expectedVal  *EffectivePermissionsType
	}{
		{
			name: `valid result`,
			regoRespJSON: `{"result": {
				"user-view": {
					"id": "user-view",
					"name": "User View",
					"hidden": false,
					"entitled_features": null
				},
				"user-manage": {
					"id": "user-manage",
					"name": "User Manage",
					"hidden": true,
					"entitled_features": []
				},
				"tag-list": {
					"id": "tag-list",
					"name": "Tag List",
					"hidden": false,
					"entitled_features": ["license.se"]
				},
				"tag-read": {
					"id": "tag-read",
					"name": "Tag Read",
					"hidden": true,
					"entitled_features": ["license.se", "license.td"]
				}
			}}`,
			expectErr: false,
			expectedVal: &EffectivePermissionsType{
				"user-view": {
					ID:               "user-view",
					Name:             "User View",
					Hidden:           false,
					EntitledFeatures: nil,
				},
				"user-manage": {
					ID:               "user-manage",
					Name:             "User Manage",
					Hidden:           true,
					EntitledFeatures: []string{},
				},
				"tag-list": {
					ID:               "tag-list",
					Name:             "Tag List",
					Hidden:           false,
					EntitledFeatures: []string{"license.se"},
				},
				"tag-read": {
					ID:               "tag-read",
					Name:             "Tag Read",
					Hidden:           true,
					EntitledFeatures: []string{"license.se", "license.td"},
				},
			},
		},
		{
			name:         `null result ok`,
			regoRespJSON: `{ "result": null }`,
			expectErr:    false,
			expectedVal:  nil,
		},
		{
			name:         `empty result ok`,
			regoRespJSON: `{ "result": {} }`,
			expectErr:    false,
			expectedVal:  &EffectivePermissionsType{},
		},
		{
			name:         `incorrect result type`,
			regoRespJSON: `[ null ]`,
			expectErr:    true,
			expectedVal:  nil,
		},
		{
			name:         `no result key`,
			regoRespJSON: `{ "rresult": null }`,
			expectErr:    false,
			expectedVal:  nil,
		},
		{
			name:         `invalid result array`,
			regoRespJSON: `{ "result": [ 1, 2 ] }`,
			expectErr:    true,
			expectedVal:  nil,
		},
	}

	stdLoggr := logrus.StandardLogger()
	ctx := context.WithValue(context.Background(), utils_test.TestingTContextKey, t)
	ctx = ctxlogrus.ToContext(ctx, logrus.NewEntry(stdLoggr))

	claims := atlas_claims.Claims{
		AccountId: "2001016",
	}
	ctx, _, err := utils_test.NewContextWithClaims(ctx, claims)
	if err != nil {
		t.Fatalf("NewContextWithClaims err: %s", err)
	}

	for nth, tm := range testMap {
		mockOpaClienter := MockOpaClienter{
			Loggr:        stdLoggr,
			RegoRespJSON: tm.regoRespJSON,
		}
		auther := NewDefaultAuthorizer("bogus_unused_application_value",
			WithOpaClienter(&mockOpaClienter),
		)

		actualVal, actualErr := auther.GetEffectivePermissions(ctx)
		t.Logf("%d: %q: actualErr=%#v, actualVal=%#v", nth, tm.name, actualVal, actualErr)

		if tm.expectErr && actualErr == nil {
			t.Errorf("%d: %q: FAIL: expected err, but got no err", nth, tm.name)
		} else if !tm.expectErr && actualErr != nil {
			t.Errorf("%d: %q: FAIL: got unexpected err=%s", nth, tm.name, actualErr)
		}

		if actualErr != nil && actualVal != nil {
			t.Errorf("%d: %q: FAIL: returned val should be nil if err returned", nth, tm.name)
		}

		if !reflect.DeepEqual(actualVal, tm.expectedVal) {
			t.Errorf("%d: %q: FAIL: expectedVal=%#v actualVal=%#v",
				nth, tm.name, tm.expectedVal, actualVal)
		}
	}
}
