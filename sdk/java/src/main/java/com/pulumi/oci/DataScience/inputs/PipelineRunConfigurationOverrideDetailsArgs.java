// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PipelineRunConfigurationOverrideDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final PipelineRunConfigurationOverrideDetailsArgs Empty = new PipelineRunConfigurationOverrideDetailsArgs();

    /**
     * The command line arguments to set for step.
     * 
     */
    @Import(name="commandLineArguments")
    private @Nullable Output<String> commandLineArguments;

    /**
     * @return The command line arguments to set for step.
     * 
     */
    public Optional<Output<String>> commandLineArguments() {
        return Optional.ofNullable(this.commandLineArguments);
    }

    /**
     * Environment variables to set for step.
     * 
     */
    @Import(name="environmentVariables")
    private @Nullable Output<Map<String,Object>> environmentVariables;

    /**
     * @return Environment variables to set for step.
     * 
     */
    public Optional<Output<Map<String,Object>>> environmentVariables() {
        return Optional.ofNullable(this.environmentVariables);
    }

    /**
     * A time bound for the execution of the step.
     * 
     */
    @Import(name="maximumRuntimeInMinutes")
    private @Nullable Output<String> maximumRuntimeInMinutes;

    /**
     * @return A time bound for the execution of the step.
     * 
     */
    public Optional<Output<String>> maximumRuntimeInMinutes() {
        return Optional.ofNullable(this.maximumRuntimeInMinutes);
    }

    /**
     * The type of pipeline.
     * 
     */
    @Import(name="type", required=true)
    private Output<String> type;

    /**
     * @return The type of pipeline.
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    private PipelineRunConfigurationOverrideDetailsArgs() {}

    private PipelineRunConfigurationOverrideDetailsArgs(PipelineRunConfigurationOverrideDetailsArgs $) {
        this.commandLineArguments = $.commandLineArguments;
        this.environmentVariables = $.environmentVariables;
        this.maximumRuntimeInMinutes = $.maximumRuntimeInMinutes;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PipelineRunConfigurationOverrideDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PipelineRunConfigurationOverrideDetailsArgs $;

        public Builder() {
            $ = new PipelineRunConfigurationOverrideDetailsArgs();
        }

        public Builder(PipelineRunConfigurationOverrideDetailsArgs defaults) {
            $ = new PipelineRunConfigurationOverrideDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param commandLineArguments The command line arguments to set for step.
         * 
         * @return builder
         * 
         */
        public Builder commandLineArguments(@Nullable Output<String> commandLineArguments) {
            $.commandLineArguments = commandLineArguments;
            return this;
        }

        /**
         * @param commandLineArguments The command line arguments to set for step.
         * 
         * @return builder
         * 
         */
        public Builder commandLineArguments(String commandLineArguments) {
            return commandLineArguments(Output.of(commandLineArguments));
        }

        /**
         * @param environmentVariables Environment variables to set for step.
         * 
         * @return builder
         * 
         */
        public Builder environmentVariables(@Nullable Output<Map<String,Object>> environmentVariables) {
            $.environmentVariables = environmentVariables;
            return this;
        }

        /**
         * @param environmentVariables Environment variables to set for step.
         * 
         * @return builder
         * 
         */
        public Builder environmentVariables(Map<String,Object> environmentVariables) {
            return environmentVariables(Output.of(environmentVariables));
        }

        /**
         * @param maximumRuntimeInMinutes A time bound for the execution of the step.
         * 
         * @return builder
         * 
         */
        public Builder maximumRuntimeInMinutes(@Nullable Output<String> maximumRuntimeInMinutes) {
            $.maximumRuntimeInMinutes = maximumRuntimeInMinutes;
            return this;
        }

        /**
         * @param maximumRuntimeInMinutes A time bound for the execution of the step.
         * 
         * @return builder
         * 
         */
        public Builder maximumRuntimeInMinutes(String maximumRuntimeInMinutes) {
            return maximumRuntimeInMinutes(Output.of(maximumRuntimeInMinutes));
        }

        /**
         * @param type The type of pipeline.
         * 
         * @return builder
         * 
         */
        public Builder type(Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type The type of pipeline.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public PipelineRunConfigurationOverrideDetailsArgs build() {
            $.type = Objects.requireNonNull($.type, "expected parameter 'type' to be non-null");
            return $;
        }
    }

}