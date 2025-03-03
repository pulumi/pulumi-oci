// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.RunbookAssociationsRollbackWorkflowDetailsWorkflow;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class RunbookAssociationsRollbackWorkflowDetails {
    /**
     * @return (Updatable) rollback Scope
     * 
     */
    private String scope;
    /**
     * @return (Updatable) Rollback Workflow for the runbook.
     * 
     */
    private List<RunbookAssociationsRollbackWorkflowDetailsWorkflow> workflows;

    private RunbookAssociationsRollbackWorkflowDetails() {}
    /**
     * @return (Updatable) rollback Scope
     * 
     */
    public String scope() {
        return this.scope;
    }
    /**
     * @return (Updatable) Rollback Workflow for the runbook.
     * 
     */
    public List<RunbookAssociationsRollbackWorkflowDetailsWorkflow> workflows() {
        return this.workflows;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(RunbookAssociationsRollbackWorkflowDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String scope;
        private List<RunbookAssociationsRollbackWorkflowDetailsWorkflow> workflows;
        public Builder() {}
        public Builder(RunbookAssociationsRollbackWorkflowDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.scope = defaults.scope;
    	      this.workflows = defaults.workflows;
        }

        @CustomType.Setter
        public Builder scope(String scope) {
            if (scope == null) {
              throw new MissingRequiredPropertyException("RunbookAssociationsRollbackWorkflowDetails", "scope");
            }
            this.scope = scope;
            return this;
        }
        @CustomType.Setter
        public Builder workflows(List<RunbookAssociationsRollbackWorkflowDetailsWorkflow> workflows) {
            if (workflows == null) {
              throw new MissingRequiredPropertyException("RunbookAssociationsRollbackWorkflowDetails", "workflows");
            }
            this.workflows = workflows;
            return this;
        }
        public Builder workflows(RunbookAssociationsRollbackWorkflowDetailsWorkflow... workflows) {
            return workflows(List.of(workflows));
        }
        public RunbookAssociationsRollbackWorkflowDetails build() {
            final var _resultValue = new RunbookAssociationsRollbackWorkflowDetails();
            _resultValue.scope = scope;
            _resultValue.workflows = workflows;
            return _resultValue;
        }
    }
}
