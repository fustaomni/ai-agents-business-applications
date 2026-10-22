# METADATA
# title: capabilities
# description: Every task is governed, or owned by a planned step until it is.
package runs.capabilities

import rego.v1

# METADATA
# title: The capability inventory is supplied, never assumed
# custom:
#   code: ERR_CAPABILITY_INPUT_MISSING
deny contains denial if {
	not input.capabilities
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no capabilities input: an absent inventory would read as every task governed",
	}
}

# METADATA
# title: Every task runs on the governance spine; ownership plans a conversion, never admits one
# custom:
#   code: ERR_CAPABILITY_OFF_SPINE
deny contains denial if {
	some task in input.capabilities.tasks
	not task.governed
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is a %s task off the governance spine (converted by %v)", [
			task.name,
			task.kind,
			task.owner,
		]),
	}
}
