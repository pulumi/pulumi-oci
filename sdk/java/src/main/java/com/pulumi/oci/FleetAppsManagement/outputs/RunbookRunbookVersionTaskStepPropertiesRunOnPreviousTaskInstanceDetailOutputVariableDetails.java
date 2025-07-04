// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class RunbookRunbookVersionTaskStepPropertiesRunOnPreviousTaskInstanceDetailOutputVariableDetails {
    /**
     * @return The name of the output variable whose value has to be mapped.
     * 
     */
    private @Nullable String outputVariableName;
    /**
     * @return The name of the task step the output variable belongs to.
     * 
     */
    private @Nullable String stepName;

    private RunbookRunbookVersionTaskStepPropertiesRunOnPreviousTaskInstanceDetailOutputVariableDetails() {}
    /**
     * @return The name of the output variable whose value has to be mapped.
     * 
     */
    public Optional<String> outputVariableName() {
        return Optional.ofNullable(this.outputVariableName);
    }
    /**
     * @return The name of the task step the output variable belongs to.
     * 
     */
    public Optional<String> stepName() {
        return Optional.ofNullable(this.stepName);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(RunbookRunbookVersionTaskStepPropertiesRunOnPreviousTaskInstanceDetailOutputVariableDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String outputVariableName;
        private @Nullable String stepName;
        public Builder() {}
        public Builder(RunbookRunbookVersionTaskStepPropertiesRunOnPreviousTaskInstanceDetailOutputVariableDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.outputVariableName = defaults.outputVariableName;
    	      this.stepName = defaults.stepName;
        }

        @CustomType.Setter
        public Builder outputVariableName(@Nullable String outputVariableName) {

            this.outputVariableName = outputVariableName;
            return this;
        }
        @CustomType.Setter
        public Builder stepName(@Nullable String stepName) {

            this.stepName = stepName;
            return this;
        }
        public RunbookRunbookVersionTaskStepPropertiesRunOnPreviousTaskInstanceDetailOutputVariableDetails build() {
            final var _resultValue = new RunbookRunbookVersionTaskStepPropertiesRunOnPreviousTaskInstanceDetailOutputVariableDetails();
            _resultValue.outputVariableName = outputVariableName;
            _resultValue.stepName = stepName;
            return _resultValue;
        }
    }
}
