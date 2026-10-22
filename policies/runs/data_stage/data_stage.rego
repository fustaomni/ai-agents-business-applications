# METADATA
# title: data_stage
# description: A data file is staged only under a name its manifest declares, by contents alone.
package runs.data_stage

import rego.v1

# METADATA
# title: The stage request is supplied, never assumed
# custom:
#   code: ERR_DATA_STAGE_INPUT_MISSING
deny contains denial if {
	not input.data_stage
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no data_stage input: an absent request would read as every copy allowed",
	}
}

# METADATA
# title: Only a name the assignment's manifest declares is staged
# custom:
#   code: ERR_DATA_STAGE_UNDECLARED
deny contains denial if {
	input.data_stage.name_declared == false
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s: %s is not a file its manifest declares", [
			input.data_stage.assignment,
			input.data_stage.name,
		]),
	}
}

# METADATA
# title: The source file exists
# custom:
#   code: ERR_DATA_STAGE_SOURCE_MISSING
deny contains denial if {
	input.data_stage.source_exists == false
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s: the source file does not exist", [input.data_stage.name]),
	}
}

# METADATA
# title: A staged file with other contents is never overwritten
# custom:
#   code: ERR_DATA_STAGE_DESTINATION_DIFFERS
deny contains denial if {
	input.data_stage.destination_exists == true
	input.data_stage.destination_identical == false
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s: a different file is already staged", [input.data_stage.name]),
	}
}
