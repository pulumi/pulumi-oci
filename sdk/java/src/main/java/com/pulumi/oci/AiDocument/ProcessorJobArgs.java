// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiDocument;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.AiDocument.inputs.ProcessorJobInputLocationArgs;
import com.pulumi.oci.AiDocument.inputs.ProcessorJobOutputLocationArgs;
import com.pulumi.oci.AiDocument.inputs.ProcessorJobProcessorConfigArgs;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ProcessorJobArgs extends com.pulumi.resources.ResourceArgs {

    public static final ProcessorJobArgs Empty = new ProcessorJobArgs();

    /**
     * The compartment identifier.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The compartment identifier.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * The display name of the processor job.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return The display name of the processor job.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The location of the inputs.
     * 
     */
    @Import(name="inputLocation", required=true)
    private Output<ProcessorJobInputLocationArgs> inputLocation;

    /**
     * @return The location of the inputs.
     * 
     */
    public Output<ProcessorJobInputLocationArgs> inputLocation() {
        return this.inputLocation;
    }

    /**
     * The object storage location where to store analysis results.
     * 
     */
    @Import(name="outputLocation", required=true)
    private Output<ProcessorJobOutputLocationArgs> outputLocation;

    /**
     * @return The object storage location where to store analysis results.
     * 
     */
    public Output<ProcessorJobOutputLocationArgs> outputLocation() {
        return this.outputLocation;
    }

    /**
     * The configuration of a processor.
     * 
     */
    @Import(name="processorConfig", required=true)
    private Output<ProcessorJobProcessorConfigArgs> processorConfig;

    /**
     * @return The configuration of a processor.
     * 
     */
    public Output<ProcessorJobProcessorConfigArgs> processorConfig() {
        return this.processorConfig;
    }

    private ProcessorJobArgs() {}

    private ProcessorJobArgs(ProcessorJobArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.inputLocation = $.inputLocation;
        this.outputLocation = $.outputLocation;
        this.processorConfig = $.processorConfig;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ProcessorJobArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ProcessorJobArgs $;

        public Builder() {
            $ = new ProcessorJobArgs();
        }

        public Builder(ProcessorJobArgs defaults) {
            $ = new ProcessorJobArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The compartment identifier.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The compartment identifier.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param displayName The display name of the processor job.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName The display name of the processor job.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param inputLocation The location of the inputs.
         * 
         * @return builder
         * 
         */
        public Builder inputLocation(Output<ProcessorJobInputLocationArgs> inputLocation) {
            $.inputLocation = inputLocation;
            return this;
        }

        /**
         * @param inputLocation The location of the inputs.
         * 
         * @return builder
         * 
         */
        public Builder inputLocation(ProcessorJobInputLocationArgs inputLocation) {
            return inputLocation(Output.of(inputLocation));
        }

        /**
         * @param outputLocation The object storage location where to store analysis results.
         * 
         * @return builder
         * 
         */
        public Builder outputLocation(Output<ProcessorJobOutputLocationArgs> outputLocation) {
            $.outputLocation = outputLocation;
            return this;
        }

        /**
         * @param outputLocation The object storage location where to store analysis results.
         * 
         * @return builder
         * 
         */
        public Builder outputLocation(ProcessorJobOutputLocationArgs outputLocation) {
            return outputLocation(Output.of(outputLocation));
        }

        /**
         * @param processorConfig The configuration of a processor.
         * 
         * @return builder
         * 
         */
        public Builder processorConfig(Output<ProcessorJobProcessorConfigArgs> processorConfig) {
            $.processorConfig = processorConfig;
            return this;
        }

        /**
         * @param processorConfig The configuration of a processor.
         * 
         * @return builder
         * 
         */
        public Builder processorConfig(ProcessorJobProcessorConfigArgs processorConfig) {
            return processorConfig(Output.of(processorConfig));
        }

        public ProcessorJobArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("ProcessorJobArgs", "compartmentId");
            }
            if ($.inputLocation == null) {
                throw new MissingRequiredPropertyException("ProcessorJobArgs", "inputLocation");
            }
            if ($.outputLocation == null) {
                throw new MissingRequiredPropertyException("ProcessorJobArgs", "outputLocation");
            }
            if ($.processorConfig == null) {
                throw new MissingRequiredPropertyException("ProcessorJobArgs", "processorConfig");
            }
            return $;
        }
    }

}
