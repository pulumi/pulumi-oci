// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.GetSchedulerDefinitionRunBookInputParameterArgument;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSchedulerDefinitionRunBookInputParameter {
    /**
     * @return Arguments for the Task
     * 
     */
    private List<GetSchedulerDefinitionRunBookInputParameterArgument> arguments;
    /**
     * @return stepName for which the input parameters are provided
     * 
     */
    private String stepName;

    private GetSchedulerDefinitionRunBookInputParameter() {}
    /**
     * @return Arguments for the Task
     * 
     */
    public List<GetSchedulerDefinitionRunBookInputParameterArgument> arguments() {
        return this.arguments;
    }
    /**
     * @return stepName for which the input parameters are provided
     * 
     */
    public String stepName() {
        return this.stepName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSchedulerDefinitionRunBookInputParameter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetSchedulerDefinitionRunBookInputParameterArgument> arguments;
        private String stepName;
        public Builder() {}
        public Builder(GetSchedulerDefinitionRunBookInputParameter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.arguments = defaults.arguments;
    	      this.stepName = defaults.stepName;
        }

        @CustomType.Setter
        public Builder arguments(List<GetSchedulerDefinitionRunBookInputParameterArgument> arguments) {
            if (arguments == null) {
              throw new MissingRequiredPropertyException("GetSchedulerDefinitionRunBookInputParameter", "arguments");
            }
            this.arguments = arguments;
            return this;
        }
        public Builder arguments(GetSchedulerDefinitionRunBookInputParameterArgument... arguments) {
            return arguments(List.of(arguments));
        }
        @CustomType.Setter
        public Builder stepName(String stepName) {
            if (stepName == null) {
              throw new MissingRequiredPropertyException("GetSchedulerDefinitionRunBookInputParameter", "stepName");
            }
            this.stepName = stepName;
            return this;
        }
        public GetSchedulerDefinitionRunBookInputParameter build() {
            final var _resultValue = new GetSchedulerDefinitionRunBookInputParameter();
            _resultValue.arguments = arguments;
            _resultValue.stepName = stepName;
            return _resultValue;
        }
    }
}
