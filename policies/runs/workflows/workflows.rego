# METADATA
# title: workflows
# description: Every workflow token grant is listed exactly, and zizmor finds nothing.
package runs.workflows

import rego.v1

# METADATA
# title: The workflow inventory is supplied, never assumed
# custom:
#   code: ERR_WORKFLOW_INPUT_MISSING
deny contains denial if {
	not input.workflows
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "no workflows input: an absent inventory would read as every grant listed",
	}
}

# METADATA
# title: zizmor completed its audit
# custom:
#   code: ERR_WORKFLOW_ZIZMOR_UNAVAILABLE
deny contains denial if {
	input.workflows
	not input.workflows.zizmor_ok
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": "zizmor did not complete its audit, so nothing it would find is ruled out",
	}
}

# METADATA
# title: zizmor finds nothing
# custom:
#   code: ERR_WORKFLOW_ZIZMOR_FINDING
deny contains denial if {
	some finding in input.workflows.findings
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("zizmor %s (%s)", [finding.ident, finding.severity]),
	}
}

# METADATA
# title: No suppression switches the audit off
# custom:
#   code: ERR_WORKFLOW_SUPPRESSION_PRESENT
deny contains denial if {
	some suppression in input.workflows.suppressions
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s:%v suppresses zizmor; a change never switches off its own gate", [
			suppression.path,
			suppression.line,
		]),
	}
}

# METADATA
# title: Every workflow declares its permissions
# custom:
#   code: ERR_WORKFLOW_DEFAULT_PERMISSIONS
deny contains denial if {
	some workflow in input.workflows.workflows
	not workflow.declares_permissions
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s declares no permissions: it inherits the repository default", [
			workflow.path,
		]),
	}
}

# METADATA
# title: No grant is write-all
# custom:
#   code: ERR_WORKFLOW_WRITE_ALL
deny contains denial if {
	some grant in input.workflows.grants
	grant.scope == "*"
	grant.access == "write"
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s grants write-all (job %v)", [grant.workflow, grant.job]),
	}
}

# METADATA
# title: Every grant is named exactly in the allow-list
# custom:
#   code: ERR_WORKFLOW_PERMISSION_UNLISTED
deny contains denial if {
	some grant in input.workflows.grants
	not _listed(grant)
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s job %v grants %s: %s in environment %v, unlisted", [
			grant.workflow,
			grant.job,
			grant.scope,
			grant.access,
			grant.environment,
		]),
	}
}

# METADATA
# title: An id-token grant runs only inside an environment
# custom:
#   code: ERR_WORKFLOW_ID_TOKEN_WITHOUT_ENVIRONMENT
deny contains denial if {
	some grant in input.workflows.grants
	grant.scope == "id-token"
	grant.access == "write"
	grant.environment == null
	denial := {
		"code": rego.metadata.rule().custom.code,
		"message": sprintf("%s job %v grants id-token: write outside an environment", [
			grant.workflow,
			grant.job,
		]),
	}
}

_listed(grant) if {
	some allowance in input.workflows.allow_list
	allowance.workflow == grant.workflow
	allowance.job == grant.job
	allowance.scope == grant.scope
	allowance.access == grant.access
	allowance.environment == grant.environment
}
