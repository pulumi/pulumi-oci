// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.inputs.SchedulerDefinitionRunBookInputParameterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SchedulerDefinitionRunBookArgs extends com.pulumi.resources.ResourceArgs {

    public static final SchedulerDefinitionRunBookArgs Empty = new SchedulerDefinitionRunBookArgs();

    /**
     * (Updatable) The ID of the Runbook
     * 
     */
    @Import(name="id", required=true)
    private Output<String> id;

    /**
     * @return (Updatable) The ID of the Runbook
     * 
     */
    public Output<String> id() {
        return this.id;
    }

    /**
     * (Updatable) Input Parameters for the Task
     * 
     */
    @Import(name="inputParameters")
    private @Nullable Output<List<SchedulerDefinitionRunBookInputParameterArgs>> inputParameters;

    /**
     * @return (Updatable) Input Parameters for the Task
     * 
     */
    public Optional<Output<List<SchedulerDefinitionRunBookInputParameterArgs>>> inputParameters() {
        return Optional.ofNullable(this.inputParameters);
    }

    private SchedulerDefinitionRunBookArgs() {}

    private SchedulerDefinitionRunBookArgs(SchedulerDefinitionRunBookArgs $) {
        this.id = $.id;
        this.inputParameters = $.inputParameters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SchedulerDefinitionRunBookArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SchedulerDefinitionRunBookArgs $;

        public Builder() {
            $ = new SchedulerDefinitionRunBookArgs();
        }

        public Builder(SchedulerDefinitionRunBookArgs defaults) {
            $ = new SchedulerDefinitionRunBookArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param id (Updatable) The ID of the Runbook
         * 
         * @return builder
         * 
         */
        public Builder id(Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id (Updatable) The ID of the Runbook
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param inputParameters (Updatable) Input Parameters for the Task
         * 
         * @return builder
         * 
         */
        public Builder inputParameters(@Nullable Output<List<SchedulerDefinitionRunBookInputParameterArgs>> inputParameters) {
            $.inputParameters = inputParameters;
            return this;
        }

        /**
         * @param inputParameters (Updatable) Input Parameters for the Task
         * 
         * @return builder
         * 
         */
        public Builder inputParameters(List<SchedulerDefinitionRunBookInputParameterArgs> inputParameters) {
            return inputParameters(Output.of(inputParameters));
        }

        /**
         * @param inputParameters (Updatable) Input Parameters for the Task
         * 
         * @return builder
         * 
         */
        public Builder inputParameters(SchedulerDefinitionRunBookInputParameterArgs... inputParameters) {
            return inputParameters(List.of(inputParameters));
        }

        public SchedulerDefinitionRunBookArgs build() {
            if ($.id == null) {
                throw new MissingRequiredPropertyException("SchedulerDefinitionRunBookArgs", "id");
            }
            return $;
        }
    }

}
