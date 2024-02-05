package authz.rbac

validate_v1 = {
	"allow": true,
}

acct_entitlements_acct_ids_is_empty {
	not input.acct_entitlements_acct_ids
}

acct_entitlements_acct_ids_is_empty {
	is_array(input.acct_entitlements_acct_ids)
	count(input.acct_entitlements_acct_ids) == 0
}

acct_entitlements_services_is_empty {
	not input.acct_entitlements_services
}

acct_entitlements_services_is_empty {
	is_array(input.acct_entitlements_services)
	count(input.acct_entitlements_services) == 0
}

acct_entitlements_api = acct_ent_result {
	# No filtering, get all acct_entitlements for all acct_entitlements_acct_ids
	acct_entitlements_acct_ids_is_empty
	acct_entitlements_services_is_empty
	acct_ent_result := account_service_features
} else = acct_ent_result {
	acct_ent_result := acct_entitlements_filtered_api
}

# Get acct_entitlements by specific acct_entitlements_acct_ids
# and specific acct_entitlements_services
acct_entitlements_filtered_api[acct_id] = acct_ent {
	is_array(input.acct_entitlements_acct_ids)
	count(input.acct_entitlements_acct_ids) > 0
	is_array(input.acct_entitlements_services)
	count(input.acct_entitlements_services) > 0
	acct_id := input.acct_entitlements_acct_ids[_]
	acct_ent := {ent_svc_name: ent_svc_feats |
		ent_svc_name := input.acct_entitlements_services[_]
		ent_svc_feats := account_service_features[acct_id][ent_svc_name]
	}
}

account_service_features := {
	"2001016": {
		"environment": [
			"ac",
			"heated-seats",
		],
		"wheel": [
			"abs",
			"alloy",
			"tpms",
		],
	},
	"2001040": {
		"environment": [
			"ac",
			"side-mirror-defogger",
		],
		"powertrain": [
			"automatic",
			"turbo",
		],
	},
	"2001230": {
		"powertrain": [
			"manual",
			"v8",
		],
		"wheel": [
			"run-flat",
		],
	},
}

merged_input = merged {
	is_string(input.jwt)
	count(trim_space(input.jwt)) > 0
	[_, payload, _] := io.jwt.decode(input.jwt)
	merged := payload
}

else = merged {
	merged := input
}

effective_permissions_api = eff_perm_result {
	eff_perm_result := account_effective_permissions[merged_input.account_id]
}

account_effective_permissions := {
	"2001016": {
		"user-view": {
			"id": "user-view",
			"name": "User View",
			"hidden": false,
			"entitled_features": null,
		},
		"user-manage": {
			"id": "user-manage",
			"name": "User Manage",
			"hidden": true,
			"entitled_features": [],
		},
		"tag-list": {
			"id": "tag-list",
			"name": "Tag List",
			"hidden": false,
			"entitled_features": ["license.se"],
		},
		"tag-read": {
			"id": "tag-read",
			"name": "Tag Read",
			"hidden": true,
			"entitled_features": ["license.se", "license.td"],
		},
	},
	"2001040": {
	},
	"2001230": {
	},
}

test_acct_entitlements_api_no_input {
	results := acct_entitlements_api
	trace(sprintf("results: %v", [results]))
	results == account_service_features
}

test_acct_entitlements_api_empty_input {
	results := acct_entitlements_api with input as {
		"acct_entitlements_acct_ids": [],
		"acct_entitlements_services": [],
	}
	trace(sprintf("results: %v", [results]))
	results == account_service_features
}

test_acct_entitlements_api_with_input {
	results := acct_entitlements_api with input as {
		"acct_entitlements_acct_ids": ["2001040", "2001230"],
		"acct_entitlements_services": ["powertrain", "wheel"],
	}
	trace(sprintf("results: %v", [results]))
	results == {
		"2001040": {
			"powertrain": [
				"automatic",
				"turbo",
			],
		},
		"2001230": {
			"powertrain": [
				"manual",
				"v8",
			],
			"wheel": [
				"run-flat",
			],
		},
	}
}

test_effective_permissions_api_with_2001016_jwt {
	results := effective_permissions_api with input as {
		"jwt": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50X2lkIjoiMjAwMTAxNiIsInNlcnZpY2UiOiJhbGwiLCJzdWJqZWN0Ijp7ImlkIjoic2VydmljZS5hbGwuMTY2MjE0MDUwNiIsInN1YmplY3RfdHlwZSI6InMycyIsImF1dGhlbnRpY2F0aW9uX3R5cGUiOiJiZWFyZXIifSwiYXVkIjoiaWItc3RrIiwiZXhwIjo0ODE1NzQwNTA2LCJpYXQiOjE2NjIxNDA1MDYsImlzcyI6ImF0bGFzLWNsYWltcyIsIm5iZiI6MTY2MjE0MDUwNn0.LiQd8R_ubBCbcC9HA0-T-xYD1KrAHpxTckGSnEFa6z1Uan8aufH8TrGmW2OZkQ5Nhn4mnONWgDARD--WIaK7VA",
	}
	trace(sprintf("results: %v", [results]))
	results == {
		"user-view": {
			"id": "user-view",
			"name": "User View",
			"hidden": false,
			"entitled_features": null,
		},
		"user-manage": {
			"id": "user-manage",
			"name": "User Manage",
			"hidden": true,
			"entitled_features": [],
		},
		"tag-list": {
			"id": "tag-list",
			"name": "Tag List",
			"hidden": false,
			"entitled_features": ["license.se"],
		},
		"tag-read": {
			"id": "tag-read",
			"name": "Tag Read",
			"hidden": true,
			"entitled_features": ["license.se", "license.td"],
		},
	}
}

# opa test -v mock_authz_policy.rego
# opa run --server mock_authz_policy.rego
# curl -X GET  -H 'Content-Type: application/json' http://localhost:8181/v1/data/authz/rbac/acct_entitlements_api | jq .
# curl -X POST -H 'Content-Type: application/json' http://localhost:8181/v1/data/authz/rbac/acct_entitlements_api | jq .

