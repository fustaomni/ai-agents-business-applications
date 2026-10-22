# METADATA
# title: ci_rerun
# description: A failed run is re-run only while Actions is steadily healthy, at the head.
package runs.ci_rerun

import rego.v1

_steady if {
	count(input.ci_rerun.actions_readings) >= input.ci_rerun.steady_required
	every reading in input.ci_rerun.actions_readings {
		reading == "operational"
	}
}

# METADATA
# title: The re-run request is supplied, never assumed
# custom:
#   code: ERR_CI_RERUN_INPUT_MISSING
deny contains denial if {
	not input.ci_rerun
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no ci_rerun input: an absent request would read as cleared to re-run",
	}
}

# METADATA
# title: There is a run to re-run
# custom:
#   code: ERR_CI_RERUN_NO_RUN
deny contains denial if {
	input.ci_rerun.run_id == null
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "the branch has no CI run to re-run",
	}
}

# METADATA
# title: The run is this branch's head
# custom:
#   code: ERR_CI_RERUN_NOT_THE_BRANCH_HEAD
deny contains denial if {
	input.ci_rerun.run_id != null
	input.ci_rerun.run_head != input.ci_rerun.branch_head
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("the run is %v, the branch head is %v", [
			input.ci_rerun.run_head,
			input.ci_rerun.branch_head,
		]),
	}
}

# METADATA
# title: The run has finished
# custom:
#   code: ERR_CI_RERUN_NOT_FINISHED
deny contains denial if {
	input.ci_rerun.run_id != null
	input.ci_rerun.run_status != "completed"
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("the run is still %v", [input.ci_rerun.run_status]),
	}
}

# METADATA
# title: The run did not already succeed
# custom:
#   code: ERR_CI_RERUN_SUCCEEDED
deny contains denial if {
	input.ci_rerun.run_conclusion == "success"
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "the run already succeeded: there is nothing to recover",
	}
}

# METADATA
# title: Actions read operational on every one of the required consecutive readings
# custom:
#   code: ERR_CI_RERUN_ACTIONS_NOT_STEADY
deny contains denial if {
	input.ci_rerun
	not _steady
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("Actions read %v; %v consecutive operational readings are required", [
			input.ci_rerun.actions_readings,
			input.ci_rerun.steady_required,
		]),
	}
}
