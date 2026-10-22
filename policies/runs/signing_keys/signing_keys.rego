# METADATA
# title: signing_keys
# description: The signing key exists, is protected outside every repository, and is published.
package runs.signing_keys

import rego.v1

# METADATA
# title: The key state is supplied, never assumed
# custom:
#   code: ERR_SIGNING_INPUT_MISSING
deny contains denial if {
	not input.signing_keys
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no signing_keys input: an absent state would read as a key in place",
	}
}

# METADATA
# title: The private key exists
# custom:
#   code: ERR_SIGNING_KEY_ABSENT
deny contains denial if {
	state := input.signing_keys
	not state.private_exists
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("no private key at %s", [state.private_path]),
	}
}

# METADATA
# title: The private key is protected and outside every repository
# custom:
#   code: ERR_SIGNING_KEY_EXPOSED
deny contains denial if {
	state := input.signing_keys
	_exposed(state)
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is exposed: mode %v, inside a repository %v", [
			state.private_path,
			state.mode,
			state.inside_repository,
		]),
	}
}

# METADATA
# title: The key is published by this repository
# custom:
#   code: ERR_SIGNING_KEY_UNLISTED
deny contains denial if {
	state := input.signing_keys
	state.private_exists
	not state.listed
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("key %v is not in contracts/signing-keys.toml", [state.keyid]),
	}
}

_exposed(state) if state.inside_repository

_exposed(state) if {
	state.private_exists
	state.mode != "0o600"
}
