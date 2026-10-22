# METADATA
# title: data_load
# description: An assignment's data is loaded only into its own declared volume, or not at all.
package runs.data_load

import rego.v1

# METADATA
# title: The load request is supplied, never assumed
# custom:
#   code: ERR_DATA_LOAD_INPUT_MISSING
deny contains denial if {
	not input.data_load
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no data_load input: an absent request would read as every upload allowed",
	}
}

# METADATA
# title: An assignment loads only what its own manifest declares
# custom:
#   code: ERR_DATA_LOAD_ASSIGNMENT_UNDECLARED
deny contains denial if {
	input.data_load.manifest_declared == false
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s: no data manifest declares what it loads", [input.data_load.assignment]),
	}
}

# METADATA
# title: The schema and volume a manifest names are resources the bundle declares
# custom:
#   code: ERR_DATA_LOAD_VOLUME_UNDECLARED
deny contains denial if {
	input.data_load.manifest_declared == true
	some kind in _undeclared
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s: the %s its manifest names is not declared by the bundle", [
			input.data_load.assignment,
			kind,
		]),
	}
}

# METADATA
# title: Every resolved name is a value, never a reference
# custom:
#   code: ERR_DATA_LOAD_REFERENCE_UNRESOLVED
deny contains denial if {
	some name in input.data_load.unresolved
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is unresolved: a path built from it would name the reference", [name]),
	}
}

# METADATA
# title: Every declared source file is staged before anything uploads
# custom:
#   code: ERR_DATA_LOAD_SOURCE_MISSING
deny contains denial if {
	some name in input.data_load.missing
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s: declared but not staged", [name]),
	}
}

_undeclared contains "schema" if input.data_load.schema_declared == false

_undeclared contains "volume" if input.data_load.volume_declared == false
