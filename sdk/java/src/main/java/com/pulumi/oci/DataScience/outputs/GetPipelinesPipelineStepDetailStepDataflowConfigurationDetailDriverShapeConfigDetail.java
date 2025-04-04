// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Double;
import java.util.Objects;

@CustomType
public final class GetPipelinesPipelineStepDetailStepDataflowConfigurationDetailDriverShapeConfigDetail {
    /**
     * @return A pipeline step run instance of type VM.Standard.E3.Flex allows memory to be specified. This specifies the size of the memory in GBs.
     * 
     */
    private Double memoryInGbs;
    /**
     * @return A pipeline step run instance of type VM.Standard.E3.Flex allows the ocpu count to be specified.
     * 
     */
    private Double ocpus;

    private GetPipelinesPipelineStepDetailStepDataflowConfigurationDetailDriverShapeConfigDetail() {}
    /**
     * @return A pipeline step run instance of type VM.Standard.E3.Flex allows memory to be specified. This specifies the size of the memory in GBs.
     * 
     */
    public Double memoryInGbs() {
        return this.memoryInGbs;
    }
    /**
     * @return A pipeline step run instance of type VM.Standard.E3.Flex allows the ocpu count to be specified.
     * 
     */
    public Double ocpus() {
        return this.ocpus;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPipelinesPipelineStepDetailStepDataflowConfigurationDetailDriverShapeConfigDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Double memoryInGbs;
        private Double ocpus;
        public Builder() {}
        public Builder(GetPipelinesPipelineStepDetailStepDataflowConfigurationDetailDriverShapeConfigDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.memoryInGbs = defaults.memoryInGbs;
    	      this.ocpus = defaults.ocpus;
        }

        @CustomType.Setter
        public Builder memoryInGbs(Double memoryInGbs) {
            if (memoryInGbs == null) {
              throw new MissingRequiredPropertyException("GetPipelinesPipelineStepDetailStepDataflowConfigurationDetailDriverShapeConfigDetail", "memoryInGbs");
            }
            this.memoryInGbs = memoryInGbs;
            return this;
        }
        @CustomType.Setter
        public Builder ocpus(Double ocpus) {
            if (ocpus == null) {
              throw new MissingRequiredPropertyException("GetPipelinesPipelineStepDetailStepDataflowConfigurationDetailDriverShapeConfigDetail", "ocpus");
            }
            this.ocpus = ocpus;
            return this;
        }
        public GetPipelinesPipelineStepDetailStepDataflowConfigurationDetailDriverShapeConfigDetail build() {
            final var _resultValue = new GetPipelinesPipelineStepDetailStepDataflowConfigurationDetailDriverShapeConfigDetail();
            _resultValue.memoryInGbs = memoryInGbs;
            _resultValue.ocpus = ocpus;
            return _resultValue;
        }
    }
}
