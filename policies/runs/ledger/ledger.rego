# METADATA
# title: ledger
# description: The run ledger's chain holds, its seals verify, and sealing never stops once begun.
package runs.ledger

import rego.v1

# METADATA
# title: The ledger report is supplied, never assumed
# custom:
#   code: ERR_LEDGER_INPUT_MISSING
deny contains denial if {
	not input.ledger
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no ledger input: an absent report would read as a ledger that holds",
	}
}

# METADATA
# title: The hash chain holds
# custom:
#   code: ERR_LEDGER_CHAIN_BROKEN
deny contains denial if {
	report := input.ledger
	not report.intact
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("the chain breaks at record %v", [report.broken_at]),
	}
}

# METADATA
# title: Every seal verifies against a published key
# custom:
#   code: ERR_LEDGER_SIGNATURE_INVALID
deny contains denial if {
	some position in input.ledger.invalid_signatures
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("record %d carries a seal that does not verify as a record seal", [position]),
	}
}

# METADATA
# title: Sealing never stops once it has begun
# custom:
#   code: ERR_LEDGER_UNSIGNED_AFTER_SIGNING
deny contains denial if {
	some position in input.ledger.unsigned_after_signing
	not position in input.ledger.waived
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("record %d is unsigned, after sealing began", [position]),
	}
}

# METADATA
# title: A waiver names exactly the record it accounts for
# custom:
#   code: ERR_LEDGER_WAIVER_UNMATCHED
deny contains denial if {
	some position in input.ledger.waivers_unmatched
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("the waiver for record %d does not name that record's unsigned run", [position]),
	}
}
