// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.inputs.RunbookVersionTaskOutputVariableMappingOutputVariableDetailsArgs;
import java.lang.String;
import java.util.Objects;


public final class RunbookVersionTaskOutputVariableMappingArgs extends com.pulumi.resources.ResourceArgs {

    public static final RunbookVersionTaskOutputVariableMappingArgs Empty = new RunbookVersionTaskOutputVariableMappingArgs();

    /**
     * (Updatable) The name of the input variable.
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return (Updatable) The name of the input variable.
     * 
     */
    public Output<String> name() {
        return this.name;
    }

    /**
     * (Updatable) The details of the output variable that will be used for
     * mapping.
     * 
     */
    @Import(name="outputVariableDetails", required=true)
    private Output<RunbookVersionTaskOutputVariableMappingOutputVariableDetailsArgs> outputVariableDetails;

    /**
     * @return (Updatable) The details of the output variable that will be used for
     * mapping.
     * 
     */
    public Output<RunbookVersionTaskOutputVariableMappingOutputVariableDetailsArgs> outputVariableDetails() {
        return this.outputVariableDetails;
    }

    private RunbookVersionTaskOutputVariableMappingArgs() {}

    private RunbookVersionTaskOutputVariableMappingArgs(RunbookVersionTaskOutputVariableMappingArgs $) {
        this.name = $.name;
        this.outputVariableDetails = $.outputVariableDetails;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(RunbookVersionTaskOutputVariableMappingArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private RunbookVersionTaskOutputVariableMappingArgs $;

        public Builder() {
            $ = new RunbookVersionTaskOutputVariableMappingArgs();
        }

        public Builder(RunbookVersionTaskOutputVariableMappingArgs defaults) {
            $ = new RunbookVersionTaskOutputVariableMappingArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param name (Updatable) The name of the input variable.
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) The name of the input variable.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param outputVariableDetails (Updatable) The details of the output variable that will be used for
         * mapping.
         * 
         * @return builder
         * 
         */
        public Builder outputVariableDetails(Output<RunbookVersionTaskOutputVariableMappingOutputVariableDetailsArgs> outputVariableDetails) {
            $.outputVariableDetails = outputVariableDetails;
            return this;
        }

        /**
         * @param outputVariableDetails (Updatable) The details of the output variable that will be used for
         * mapping.
         * 
         * @return builder
         * 
         */
        public Builder outputVariableDetails(RunbookVersionTaskOutputVariableMappingOutputVariableDetailsArgs outputVariableDetails) {
            return outputVariableDetails(Output.of(outputVariableDetails));
        }

        public RunbookVersionTaskOutputVariableMappingArgs build() {
            if ($.name == null) {
                throw new MissingRequiredPropertyException("RunbookVersionTaskOutputVariableMappingArgs", "name");
            }
            if ($.outputVariableDetails == null) {
                throw new MissingRequiredPropertyException("RunbookVersionTaskOutputVariableMappingArgs", "outputVariableDetails");
            }
            return $;
        }
    }

}
