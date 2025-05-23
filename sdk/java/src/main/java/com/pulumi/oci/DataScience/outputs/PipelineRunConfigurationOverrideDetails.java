// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class PipelineRunConfigurationOverrideDetails {
    /**
     * @return The command line arguments to set for steps in the pipeline.
     * 
     */
    private @Nullable String commandLineArguments;
    /**
     * @return Environment variables to set for steps in the pipeline.
     * 
     */
    private @Nullable Map<String,String> environmentVariables;
    /**
     * @return A time bound for the execution of the entire Pipeline. Timer starts when the Pipeline Run is in progress.
     * 
     */
    private @Nullable String maximumRuntimeInMinutes;
    /**
     * @return The type of pipeline.
     * 
     */
    private String type;

    private PipelineRunConfigurationOverrideDetails() {}
    /**
     * @return The command line arguments to set for steps in the pipeline.
     * 
     */
    public Optional<String> commandLineArguments() {
        return Optional.ofNullable(this.commandLineArguments);
    }
    /**
     * @return Environment variables to set for steps in the pipeline.
     * 
     */
    public Map<String,String> environmentVariables() {
        return this.environmentVariables == null ? Map.of() : this.environmentVariables;
    }
    /**
     * @return A time bound for the execution of the entire Pipeline. Timer starts when the Pipeline Run is in progress.
     * 
     */
    public Optional<String> maximumRuntimeInMinutes() {
        return Optional.ofNullable(this.maximumRuntimeInMinutes);
    }
    /**
     * @return The type of pipeline.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(PipelineRunConfigurationOverrideDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String commandLineArguments;
        private @Nullable Map<String,String> environmentVariables;
        private @Nullable String maximumRuntimeInMinutes;
        private String type;
        public Builder() {}
        public Builder(PipelineRunConfigurationOverrideDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.commandLineArguments = defaults.commandLineArguments;
    	      this.environmentVariables = defaults.environmentVariables;
    	      this.maximumRuntimeInMinutes = defaults.maximumRuntimeInMinutes;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder commandLineArguments(@Nullable String commandLineArguments) {

            this.commandLineArguments = commandLineArguments;
            return this;
        }
        @CustomType.Setter
        public Builder environmentVariables(@Nullable Map<String,String> environmentVariables) {

            this.environmentVariables = environmentVariables;
            return this;
        }
        @CustomType.Setter
        public Builder maximumRuntimeInMinutes(@Nullable String maximumRuntimeInMinutes) {

            this.maximumRuntimeInMinutes = maximumRuntimeInMinutes;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("PipelineRunConfigurationOverrideDetails", "type");
            }
            this.type = type;
            return this;
        }
        public PipelineRunConfigurationOverrideDetails build() {
            final var _resultValue = new PipelineRunConfigurationOverrideDetails();
            _resultValue.commandLineArguments = commandLineArguments;
            _resultValue.environmentVariables = environmentVariables;
            _resultValue.maximumRuntimeInMinutes = maximumRuntimeInMinutes;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
