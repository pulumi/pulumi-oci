// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Double;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class PipelineStepDetailStepInfrastructureConfigurationDetailsShapeConfigDetails {
    /**
     * @return A pipeline step run instance of type VM.Standard.E3.Flex allows memory to be specified. This specifies the size of the memory in GBs.
     * 
     */
    private @Nullable Double memoryInGbs;
    /**
     * @return A pipeline step run instance of type VM.Standard.E3.Flex allows the ocpu count to be specified.
     * 
     */
    private @Nullable Double ocpus;

    private PipelineStepDetailStepInfrastructureConfigurationDetailsShapeConfigDetails() {}
    /**
     * @return A pipeline step run instance of type VM.Standard.E3.Flex allows memory to be specified. This specifies the size of the memory in GBs.
     * 
     */
    public Optional<Double> memoryInGbs() {
        return Optional.ofNullable(this.memoryInGbs);
    }
    /**
     * @return A pipeline step run instance of type VM.Standard.E3.Flex allows the ocpu count to be specified.
     * 
     */
    public Optional<Double> ocpus() {
        return Optional.ofNullable(this.ocpus);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(PipelineStepDetailStepInfrastructureConfigurationDetailsShapeConfigDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Double memoryInGbs;
        private @Nullable Double ocpus;
        public Builder() {}
        public Builder(PipelineStepDetailStepInfrastructureConfigurationDetailsShapeConfigDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.memoryInGbs = defaults.memoryInGbs;
    	      this.ocpus = defaults.ocpus;
        }

        @CustomType.Setter
        public Builder memoryInGbs(@Nullable Double memoryInGbs) {
            this.memoryInGbs = memoryInGbs;
            return this;
        }
        @CustomType.Setter
        public Builder ocpus(@Nullable Double ocpus) {
            this.ocpus = ocpus;
            return this;
        }
        public PipelineStepDetailStepInfrastructureConfigurationDetailsShapeConfigDetails build() {
            final var o = new PipelineStepDetailStepInfrastructureConfigurationDetailsShapeConfigDetails();
            o.memoryInGbs = memoryInGbs;
            o.ocpus = ocpus;
            return o;
        }
    }
}