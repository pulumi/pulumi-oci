// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Double;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PipelineStepDetailStepInfrastructureConfigurationDetailsShapeConfigDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final PipelineStepDetailStepInfrastructureConfigurationDetailsShapeConfigDetailsArgs Empty = new PipelineStepDetailStepInfrastructureConfigurationDetailsShapeConfigDetailsArgs();

    /**
     * (Updatable) A pipeline step run instance of type VM.Standard.E3.Flex allows memory to be specified. This specifies the size of the memory in GBs.
     * 
     */
    @Import(name="memoryInGbs")
    private @Nullable Output<Double> memoryInGbs;

    /**
     * @return (Updatable) A pipeline step run instance of type VM.Standard.E3.Flex allows memory to be specified. This specifies the size of the memory in GBs.
     * 
     */
    public Optional<Output<Double>> memoryInGbs() {
        return Optional.ofNullable(this.memoryInGbs);
    }

    /**
     * (Updatable) A pipeline step run instance of type VM.Standard.E3.Flex allows the ocpu count to be specified.
     * 
     */
    @Import(name="ocpus")
    private @Nullable Output<Double> ocpus;

    /**
     * @return (Updatable) A pipeline step run instance of type VM.Standard.E3.Flex allows the ocpu count to be specified.
     * 
     */
    public Optional<Output<Double>> ocpus() {
        return Optional.ofNullable(this.ocpus);
    }

    private PipelineStepDetailStepInfrastructureConfigurationDetailsShapeConfigDetailsArgs() {}

    private PipelineStepDetailStepInfrastructureConfigurationDetailsShapeConfigDetailsArgs(PipelineStepDetailStepInfrastructureConfigurationDetailsShapeConfigDetailsArgs $) {
        this.memoryInGbs = $.memoryInGbs;
        this.ocpus = $.ocpus;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PipelineStepDetailStepInfrastructureConfigurationDetailsShapeConfigDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PipelineStepDetailStepInfrastructureConfigurationDetailsShapeConfigDetailsArgs $;

        public Builder() {
            $ = new PipelineStepDetailStepInfrastructureConfigurationDetailsShapeConfigDetailsArgs();
        }

        public Builder(PipelineStepDetailStepInfrastructureConfigurationDetailsShapeConfigDetailsArgs defaults) {
            $ = new PipelineStepDetailStepInfrastructureConfigurationDetailsShapeConfigDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param memoryInGbs (Updatable) A pipeline step run instance of type VM.Standard.E3.Flex allows memory to be specified. This specifies the size of the memory in GBs.
         * 
         * @return builder
         * 
         */
        public Builder memoryInGbs(@Nullable Output<Double> memoryInGbs) {
            $.memoryInGbs = memoryInGbs;
            return this;
        }

        /**
         * @param memoryInGbs (Updatable) A pipeline step run instance of type VM.Standard.E3.Flex allows memory to be specified. This specifies the size of the memory in GBs.
         * 
         * @return builder
         * 
         */
        public Builder memoryInGbs(Double memoryInGbs) {
            return memoryInGbs(Output.of(memoryInGbs));
        }

        /**
         * @param ocpus (Updatable) A pipeline step run instance of type VM.Standard.E3.Flex allows the ocpu count to be specified.
         * 
         * @return builder
         * 
         */
        public Builder ocpus(@Nullable Output<Double> ocpus) {
            $.ocpus = ocpus;
            return this;
        }

        /**
         * @param ocpus (Updatable) A pipeline step run instance of type VM.Standard.E3.Flex allows the ocpu count to be specified.
         * 
         * @return builder
         * 
         */
        public Builder ocpus(Double ocpus) {
            return ocpus(Output.of(ocpus));
        }

        public PipelineStepDetailStepInfrastructureConfigurationDetailsShapeConfigDetailsArgs build() {
            return $;
        }
    }

}
