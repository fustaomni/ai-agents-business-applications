# METADATA
# title: assertions
# description: No test asserts over a subject it has not proven to exist.
package runs.assertions

import rego.v1

# METADATA
# title: The assertion inventory is supplied, never assumed
# custom:
#   code: ERR_ASSERTION_INPUT_MISSING
deny contains denial if {
	not input.assertions
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no assertions input: an absent inventory would read as no vacuous claim",
	}
}

# METADATA
# title: The audit examined something
# custom:
#   code: ERR_ASSERTION_NOTHING_SCANNED
deny contains denial if {
	input.assertions.files_scanned == 0
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no test file was scanned: an audit of nothing passes having examined nothing",
	}
}

# METADATA
# title: Every claim ranges over a subject proven to exist
# custom:
#   code: ERR_ASSERTION_VACUOUS
deny contains denial if {
	some finding in input.assertions.findings
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s:%d %s over %s, never proven non-empty: pin it with nonempty()", [
			finding.path,
			finding.line,
			finding.kind,
			finding.subject,
		]),
	}
}
