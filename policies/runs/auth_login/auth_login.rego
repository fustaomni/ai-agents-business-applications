# METADATA
# title: auth_login
# description: Declared profiles are logged in on secure hosts; a declared one is never removed.
package runs.auth_login

import rego.v1

# METADATA
# title: The login plan is supplied, never assumed
# custom:
#   code: ERR_AUTH_INPUT_MISSING
deny contains denial if {
	not input.auth_login
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no auth_login input: an absent plan would read as nothing to log in",
	}
}

# METADATA
# title: An account profile names its account
# custom:
#   code: ERR_AUTH_ACCOUNT_ID_MISSING
deny contains denial if {
	some profile in input.auth_login.desired
	profile.level == "account"
	profile.account_id == null
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is an account profile with no account id", [profile.name]),
	}
}

# METADATA
# title: Every declared host is https
# custom:
#   code: ERR_AUTH_HOST_INSECURE
deny contains denial if {
	some declared in input.auth_login.desired
	not startswith(declared.host, "https://")
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s would log in to %s, which is not https", [declared.name, declared.host]),
	}
}

# METADATA
# title: A declared profile is never removed
# custom:
#   code: ERR_AUTH_STALE_DESIRED
deny contains denial if {
	some name in input.auth_login.stale
	some wanted in input.auth_login.desired
	wanted.name == name
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is declared, so it is never removed as stale", [name]),
	}
}
