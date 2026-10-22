# METADATA
# title: nix_lock
# description: A refreshed nixpkgs lock is kept only if the CI flake checker would accept it.
package runs.nix_lock

import rego.v1

# METADATA
# title: The lock update request is supplied, never assumed
# custom:
#   code: ERR_NIX_LOCK_INPUT_MISSING
deny contains denial if {
	not input.nix_lock
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no nix_lock input: an absent request would read as a lock kept",
	}
}

# METADATA
# title: The refreshed input is younger than the CI flake checker allows
# custom:
#   code: ERR_NIX_LOCK_STALE
deny contains denial if {
	input.nix_lock.age_days >= input.nix_lock.max_age_days
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is %v days old; the CI flake checker requires under %v", [
			input.nix_lock.input_name,
			input.nix_lock.age_days,
			input.nix_lock.max_age_days,
		]),
	}
}

# METADATA
# title: The refreshed input is owned by the NixOS organisation
# custom:
#   code: ERR_NIX_LOCK_OWNER
deny contains denial if {
	lower(input.nix_lock.owner) != "nixos"
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is owned by %s, not NixOS", [
			input.nix_lock.input_name,
			input.nix_lock.owner,
		]),
	}
}

# METADATA
# title: The refreshed input follows nixpkgs-unstable, as flake.nix declares
# custom:
#   code: ERR_NIX_LOCK_REF
deny contains denial if {
	input.nix_lock.ref != "nixpkgs-unstable"
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s follows %v, not nixpkgs-unstable", [
			input.nix_lock.input_name,
			input.nix_lock.ref,
		]),
	}
}
