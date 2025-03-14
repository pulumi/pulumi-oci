// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.inputs.RunbookAssociationsTaskOutputVariableMappingArgs;
import com.pulumi.oci.FleetAppsManagement.inputs.RunbookAssociationsTaskStepPropertiesArgs;
import com.pulumi.oci.FleetAppsManagement.inputs.RunbookAssociationsTaskTaskRecordDetailsArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class RunbookAssociationsTaskArgs extends com.pulumi.resources.ResourceArgs {

    public static final RunbookAssociationsTaskArgs Empty = new RunbookAssociationsTaskArgs();

    /**
     * (Updatable) The association type of the task
     * 
     */
    @Import(name="associationType", required=true)
    private Output<String> associationType;

    /**
     * @return (Updatable) The association type of the task
     * 
     */
    public Output<String> associationType() {
        return this.associationType;
    }

    /**
     * (Updatable) Mapping output variables of previous tasks to the input variables of the current task.
     * 
     */
    @Import(name="outputVariableMappings")
    private @Nullable Output<List<RunbookAssociationsTaskOutputVariableMappingArgs>> outputVariableMappings;

    /**
     * @return (Updatable) Mapping output variables of previous tasks to the input variables of the current task.
     * 
     */
    public Optional<Output<List<RunbookAssociationsTaskOutputVariableMappingArgs>>> outputVariableMappings() {
        return Optional.ofNullable(this.outputVariableMappings);
    }

    /**
     * (Updatable) The name of the task step.
     * 
     */
    @Import(name="stepName", required=true)
    private Output<String> stepName;

    /**
     * @return (Updatable) The name of the task step.
     * 
     */
    public Output<String> stepName() {
        return this.stepName;
    }

    /**
     * (Updatable) The properties of the component.
     * 
     */
    @Import(name="stepProperties")
    private @Nullable Output<RunbookAssociationsTaskStepPropertiesArgs> stepProperties;

    /**
     * @return (Updatable) The properties of the component.
     * 
     */
    public Optional<Output<RunbookAssociationsTaskStepPropertiesArgs>> stepProperties() {
        return Optional.ofNullable(this.stepProperties);
    }

    /**
     * (Updatable) The details of the task.
     * 
     */
    @Import(name="taskRecordDetails", required=true)
    private Output<RunbookAssociationsTaskTaskRecordDetailsArgs> taskRecordDetails;

    /**
     * @return (Updatable) The details of the task.
     * 
     */
    public Output<RunbookAssociationsTaskTaskRecordDetailsArgs> taskRecordDetails() {
        return this.taskRecordDetails;
    }

    private RunbookAssociationsTaskArgs() {}

    private RunbookAssociationsTaskArgs(RunbookAssociationsTaskArgs $) {
        this.associationType = $.associationType;
        this.outputVariableMappings = $.outputVariableMappings;
        this.stepName = $.stepName;
        this.stepProperties = $.stepProperties;
        this.taskRecordDetails = $.taskRecordDetails;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(RunbookAssociationsTaskArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private RunbookAssociationsTaskArgs $;

        public Builder() {
            $ = new RunbookAssociationsTaskArgs();
        }

        public Builder(RunbookAssociationsTaskArgs defaults) {
            $ = new RunbookAssociationsTaskArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param associationType (Updatable) The association type of the task
         * 
         * @return builder
         * 
         */
        public Builder associationType(Output<String> associationType) {
            $.associationType = associationType;
            return this;
        }

        /**
         * @param associationType (Updatable) The association type of the task
         * 
         * @return builder
         * 
         */
        public Builder associationType(String associationType) {
            return associationType(Output.of(associationType));
        }

        /**
         * @param outputVariableMappings (Updatable) Mapping output variables of previous tasks to the input variables of the current task.
         * 
         * @return builder
         * 
         */
        public Builder outputVariableMappings(@Nullable Output<List<RunbookAssociationsTaskOutputVariableMappingArgs>> outputVariableMappings) {
            $.outputVariableMappings = outputVariableMappings;
            return this;
        }

        /**
         * @param outputVariableMappings (Updatable) Mapping output variables of previous tasks to the input variables of the current task.
         * 
         * @return builder
         * 
         */
        public Builder outputVariableMappings(List<RunbookAssociationsTaskOutputVariableMappingArgs> outputVariableMappings) {
            return outputVariableMappings(Output.of(outputVariableMappings));
        }

        /**
         * @param outputVariableMappings (Updatable) Mapping output variables of previous tasks to the input variables of the current task.
         * 
         * @return builder
         * 
         */
        public Builder outputVariableMappings(RunbookAssociationsTaskOutputVariableMappingArgs... outputVariableMappings) {
            return outputVariableMappings(List.of(outputVariableMappings));
        }

        /**
         * @param stepName (Updatable) The name of the task step.
         * 
         * @return builder
         * 
         */
        public Builder stepName(Output<String> stepName) {
            $.stepName = stepName;
            return this;
        }

        /**
         * @param stepName (Updatable) The name of the task step.
         * 
         * @return builder
         * 
         */
        public Builder stepName(String stepName) {
            return stepName(Output.of(stepName));
        }

        /**
         * @param stepProperties (Updatable) The properties of the component.
         * 
         * @return builder
         * 
         */
        public Builder stepProperties(@Nullable Output<RunbookAssociationsTaskStepPropertiesArgs> stepProperties) {
            $.stepProperties = stepProperties;
            return this;
        }

        /**
         * @param stepProperties (Updatable) The properties of the component.
         * 
         * @return builder
         * 
         */
        public Builder stepProperties(RunbookAssociationsTaskStepPropertiesArgs stepProperties) {
            return stepProperties(Output.of(stepProperties));
        }

        /**
         * @param taskRecordDetails (Updatable) The details of the task.
         * 
         * @return builder
         * 
         */
        public Builder taskRecordDetails(Output<RunbookAssociationsTaskTaskRecordDetailsArgs> taskRecordDetails) {
            $.taskRecordDetails = taskRecordDetails;
            return this;
        }

        /**
         * @param taskRecordDetails (Updatable) The details of the task.
         * 
         * @return builder
         * 
         */
        public Builder taskRecordDetails(RunbookAssociationsTaskTaskRecordDetailsArgs taskRecordDetails) {
            return taskRecordDetails(Output.of(taskRecordDetails));
        }

        public RunbookAssociationsTaskArgs build() {
            if ($.associationType == null) {
                throw new MissingRequiredPropertyException("RunbookAssociationsTaskArgs", "associationType");
            }
            if ($.stepName == null) {
                throw new MissingRequiredPropertyException("RunbookAssociationsTaskArgs", "stepName");
            }
            if ($.taskRecordDetails == null) {
                throw new MissingRequiredPropertyException("RunbookAssociationsTaskArgs", "taskRecordDetails");
            }
            return $;
        }
    }

}
