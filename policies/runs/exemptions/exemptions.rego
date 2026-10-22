# METADATA
# title: exemptions
# description: Every registered exemption is live and names a path that exists (D.174).
package runs.exemptions

import rego.v1

# METADATA
# title: The exemption inventory is supplied, never assumed
# custom:
#   code: ERR_EXEMPTION_INPUT_MISSING
deny contains denial if {
	not input.exemptions
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no exemptions input: an absent inventory would read as every exemption live",
	}
}

# METADATA
# title: An exemption has not expired
# custom:
#   code: ERR_EXEMPTION_EXPIRED
deny contains denial if {
	some exemption in input.exemptions.exemptions
	exemption.expires < input.exemptions.today
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%v at %v expired on %v; renew it with its reason or remove it", [
			exemption.rule,
			exemption.path,
			exemption.expires,
		]),
	}
}

# METADATA
# title: An exemption names a path that exists
# custom:
#   code: ERR_EXEMPTION_PATH_MISSING
deny contains denial if {
	some exemption in input.exemptions.exemptions
	not exemption.path_exists
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%v names %v, which no longer exists", [exemption.rule, exemption.path]),
	}
}
