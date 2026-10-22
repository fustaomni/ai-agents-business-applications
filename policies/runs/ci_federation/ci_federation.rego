# METADATA
# title: ci_federation
# description: CI's federation trust names GitHub, this account, this repository and the CI principal.
package runs.ci_federation

import rego.v1

# METADATA
# title: The federation plan is supplied, never assumed
# custom:
#   code: ERR_FEDERATION_INPUT_MISSING
deny contains denial if {
	not input.ci_federation
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no ci_federation input: an absent plan would read as a trust to create",
	}
}

# METADATA
# title: The CI principal exists
# custom:
#   code: ERR_FEDERATION_PRINCIPAL_MISSING
deny contains denial if {
	input.ci_federation.principal == null
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("no service principal holds the client id %s", [
			input.ci_federation.ci_client_id,
		]),
	}
}

# METADATA
# title: The principal is the declared CI principal
# custom:
#   code: ERR_FEDERATION_PRINCIPAL_FOREIGN
deny contains denial if {
	federation := input.ci_federation
	federation.principal != null
	_foreign(federation)
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s (%s) is not the declared CI principal %s (%s)", [
			federation.principal.display_name,
			federation.principal.application_id,
			federation.ci_principal,
			federation.ci_client_id,
		]),
	}
}

# METADATA
# title: The issuer is GitHub Actions
# custom:
#   code: ERR_FEDERATION_ISSUER
deny contains denial if {
	input.ci_federation.desired.issuer != "https://token.actions.githubusercontent.com"
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("issuer %s is not GitHub Actions", [input.ci_federation.desired.issuer]),
	}
}

# METADATA
# title: The audience is exactly this account
# custom:
#   code: ERR_FEDERATION_AUDIENCE
deny contains denial if {
	input.ci_federation.desired.audiences != [input.ci_federation.account_id]
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("audiences %v are not exactly this account", [
			input.ci_federation.desired.audiences,
		]),
	}
}

# METADATA
# title: The subject is exactly this repository's environment
# custom:
#   code: ERR_FEDERATION_SUBJECT
deny contains denial if {
	federation := input.ci_federation
	expected := sprintf("repo:%s:environment:%s", [federation.repository_path, federation.environment])
	federation.desired.subject != expected
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("subject %v is not %s", [federation.desired.subject, expected]),
	}
}

_foreign(federation) if federation.principal.display_name != federation.ci_principal

_foreign(federation) if federation.principal.application_id != federation.ci_client_id
