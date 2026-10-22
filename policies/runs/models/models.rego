# METADATA
# title: models
# description: Every model derives from Contract or Reading; the direct-subclass baseline only shrinks.
package runs.models

import rego.v1

# METADATA
# title: The model inventory is supplied, never assumed
# custom:
#   code: ERR_MODELS_INPUT_MISSING
deny contains denial if {
	not input.models
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no models input: an absent inventory would read as a clean one",
	}
}

# METADATA
# title: An audit that scanned no file proves nothing
# custom:
#   code: ERR_MODELS_NOTHING_SCANNED
deny contains denial if {
	input.models.files_scanned == 0
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no script was scanned: the audit judged nothing",
	}
}

# METADATA
# title: A new model derives from Contract or Reading, never BaseModel
# custom:
#   code: ERR_MODELS_UNBASELINED
deny contains denial if {
	some finding in input.models.findings
	finding.kind == "unbaselined"
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s derives from BaseModel directly: use Contract or Reading", [
			finding.entry,
		]),
	}
}

# METADATA
# title: The baseline lists only what is still true, so it can only shrink
# custom:
#   code: ERR_MODELS_STALE
deny contains denial if {
	some finding in input.models.findings
	finding.kind == "stale"
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s is listed but no longer derives from BaseModel: remove it", [
			finding.entry,
		]),
	}
}
