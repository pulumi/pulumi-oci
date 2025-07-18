// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.GetRunbookRunbookVersionExecutionWorkflowDetailWorkflowStep;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetRunbookRunbookVersionExecutionWorkflowDetailWorkflow {
    /**
     * @return Name of the group.
     * 
     */
    private String groupName;
    /**
     * @return Tasks within the Group. Provide the stepName for all applicable tasks.
     * 
     */
    private List<GetRunbookRunbookVersionExecutionWorkflowDetailWorkflowStep> steps;
    /**
     * @return The type of the runbook.
     * 
     */
    private String type;

    private GetRunbookRunbookVersionExecutionWorkflowDetailWorkflow() {}
    /**
     * @return Name of the group.
     * 
     */
    public String groupName() {
        return this.groupName;
    }
    /**
     * @return Tasks within the Group. Provide the stepName for all applicable tasks.
     * 
     */
    public List<GetRunbookRunbookVersionExecutionWorkflowDetailWorkflowStep> steps() {
        return this.steps;
    }
    /**
     * @return The type of the runbook.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRunbookRunbookVersionExecutionWorkflowDetailWorkflow defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String groupName;
        private List<GetRunbookRunbookVersionExecutionWorkflowDetailWorkflowStep> steps;
        private String type;
        public Builder() {}
        public Builder(GetRunbookRunbookVersionExecutionWorkflowDetailWorkflow defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.groupName = defaults.groupName;
    	      this.steps = defaults.steps;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder groupName(String groupName) {
            if (groupName == null) {
              throw new MissingRequiredPropertyException("GetRunbookRunbookVersionExecutionWorkflowDetailWorkflow", "groupName");
            }
            this.groupName = groupName;
            return this;
        }
        @CustomType.Setter
        public Builder steps(List<GetRunbookRunbookVersionExecutionWorkflowDetailWorkflowStep> steps) {
            if (steps == null) {
              throw new MissingRequiredPropertyException("GetRunbookRunbookVersionExecutionWorkflowDetailWorkflow", "steps");
            }
            this.steps = steps;
            return this;
        }
        public Builder steps(GetRunbookRunbookVersionExecutionWorkflowDetailWorkflowStep... steps) {
            return steps(List.of(steps));
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetRunbookRunbookVersionExecutionWorkflowDetailWorkflow", "type");
            }
            this.type = type;
            return this;
        }
        public GetRunbookRunbookVersionExecutionWorkflowDetailWorkflow build() {
            final var _resultValue = new GetRunbookRunbookVersionExecutionWorkflowDetailWorkflow();
            _resultValue.groupName = groupName;
            _resultValue.steps = steps;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
