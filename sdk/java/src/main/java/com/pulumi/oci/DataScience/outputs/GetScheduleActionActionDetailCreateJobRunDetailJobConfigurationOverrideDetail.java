// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetScheduleActionActionDetailCreateJobRunDetailJobConfigurationOverrideDetail {
    /**
     * @return The command line arguments to set for step.
     * 
     */
    private String commandLineArguments;
    /**
     * @return Environment variables to set for step.
     * 
     */
    private Map<String,String> environmentVariables;
    /**
     * @return The type of job.
     * 
     */
    private String jobType;
    /**
     * @return A time bound for the execution of the step.
     * 
     */
    private String maximumRuntimeInMinutes;

    private GetScheduleActionActionDetailCreateJobRunDetailJobConfigurationOverrideDetail() {}
    /**
     * @return The command line arguments to set for step.
     * 
     */
    public String commandLineArguments() {
        return this.commandLineArguments;
    }
    /**
     * @return Environment variables to set for step.
     * 
     */
    public Map<String,String> environmentVariables() {
        return this.environmentVariables;
    }
    /**
     * @return The type of job.
     * 
     */
    public String jobType() {
        return this.jobType;
    }
    /**
     * @return A time bound for the execution of the step.
     * 
     */
    public String maximumRuntimeInMinutes() {
        return this.maximumRuntimeInMinutes;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetScheduleActionActionDetailCreateJobRunDetailJobConfigurationOverrideDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String commandLineArguments;
        private Map<String,String> environmentVariables;
        private String jobType;
        private String maximumRuntimeInMinutes;
        public Builder() {}
        public Builder(GetScheduleActionActionDetailCreateJobRunDetailJobConfigurationOverrideDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.commandLineArguments = defaults.commandLineArguments;
    	      this.environmentVariables = defaults.environmentVariables;
    	      this.jobType = defaults.jobType;
    	      this.maximumRuntimeInMinutes = defaults.maximumRuntimeInMinutes;
        }

        @CustomType.Setter
        public Builder commandLineArguments(String commandLineArguments) {
            if (commandLineArguments == null) {
              throw new MissingRequiredPropertyException("GetScheduleActionActionDetailCreateJobRunDetailJobConfigurationOverrideDetail", "commandLineArguments");
            }
            this.commandLineArguments = commandLineArguments;
            return this;
        }
        @CustomType.Setter
        public Builder environmentVariables(Map<String,String> environmentVariables) {
            if (environmentVariables == null) {
              throw new MissingRequiredPropertyException("GetScheduleActionActionDetailCreateJobRunDetailJobConfigurationOverrideDetail", "environmentVariables");
            }
            this.environmentVariables = environmentVariables;
            return this;
        }
        @CustomType.Setter
        public Builder jobType(String jobType) {
            if (jobType == null) {
              throw new MissingRequiredPropertyException("GetScheduleActionActionDetailCreateJobRunDetailJobConfigurationOverrideDetail", "jobType");
            }
            this.jobType = jobType;
            return this;
        }
        @CustomType.Setter
        public Builder maximumRuntimeInMinutes(String maximumRuntimeInMinutes) {
            if (maximumRuntimeInMinutes == null) {
              throw new MissingRequiredPropertyException("GetScheduleActionActionDetailCreateJobRunDetailJobConfigurationOverrideDetail", "maximumRuntimeInMinutes");
            }
            this.maximumRuntimeInMinutes = maximumRuntimeInMinutes;
            return this;
        }
        public GetScheduleActionActionDetailCreateJobRunDetailJobConfigurationOverrideDetail build() {
            final var _resultValue = new GetScheduleActionActionDetailCreateJobRunDetailJobConfigurationOverrideDetail();
            _resultValue.commandLineArguments = commandLineArguments;
            _resultValue.environmentVariables = environmentVariables;
            _resultValue.jobType = jobType;
            _resultValue.maximumRuntimeInMinutes = maximumRuntimeInMinutes;
            return _resultValue;
        }
    }
}
