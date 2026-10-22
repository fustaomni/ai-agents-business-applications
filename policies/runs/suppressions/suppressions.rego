# METADATA
# title: suppressions
# description: An inline suppression stands only while a live exemption registers it (D.219).
package runs.suppressions

import rego.v1

# METADATA
# title: The suppression inventory is supplied, never assumed
# custom:
#   code: ERR_SUPPRESSION_INPUT_MISSING
deny contains denial if {
	not input.suppressions
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no suppressions input: an absent inventory would read as none found",
	}
}

# METADATA
# title: Every inline suppression is registered
# custom:
#   code: ERR_SUPPRESSION_UNREGISTERED
deny contains denial if {
	some found in input.suppressions.found
	not found.registered
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%v:%v carries %v with no live exemption; fix the code, or register it", [
			found.path,
			found.line,
			found.kind,
		]),
	}
}
