# METADATA
# title: evidence
# description: Evidence contracts hold observations only; policy draws every conclusion.
package runs.evidence

import rego.v1

# METADATA
# title: The evidence inventory is supplied, never assumed
# custom:
#   code: ERR_EVIDENCE_INPUT_MISSING
deny contains denial if {
	not input.evidence
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no evidence input: an absent inventory would read as a clean one",
	}
}

# METADATA
# title: An audit that found no evidence contract proves nothing
# custom:
#   code: ERR_EVIDENCE_NONE_FOUND
deny contains denial if {
	count(input.evidence.contracts) == 0
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no evidence contract was found: the audit judged nothing",
	}
}

# METADATA
# title: Evidence holds observations, never a conclusion
# custom:
#   code: ERR_EVIDENCE_CONCLUSION
deny contains denial if {
	some finding in input.evidence.findings
	finding.kind == "conclusion"
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s:%d %s.%s names a conclusion; evidence holds observations only", [
			finding.path,
			finding.line,
			finding.contract,
			finding.field,
		]),
	}
}

# METADATA
# title: Every evaluate() argument resolves to its evidence contract
# custom:
#   code: ERR_EVIDENCE_UNRESOLVED
deny contains denial if {
	some finding in input.evidence.findings
	finding.kind == "unresolved"
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s:%d passes %s to evaluate(), resolved to no evidence contract", [
			finding.path,
			finding.line,
			finding.contract,
		]),
	}
}
