// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataScience.outputs.GetPipelineRunsPipelineRunStepOverrideDetailStepConfigurationDetail;
import com.pulumi.oci.DataScience.outputs.GetPipelineRunsPipelineRunStepOverrideDetailStepContainerConfigurationDetail;
import com.pulumi.oci.DataScience.outputs.GetPipelineRunsPipelineRunStepOverrideDetailStepDataflowConfigurationDetail;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetPipelineRunsPipelineRunStepOverrideDetail {
    /**
     * @return The configuration details of a step.
     * 
     */
    private List<GetPipelineRunsPipelineRunStepOverrideDetailStepConfigurationDetail> stepConfigurationDetails;
    /**
     * @return Container Details for a step in pipeline.
     * 
     */
    private List<GetPipelineRunsPipelineRunStepOverrideDetailStepContainerConfigurationDetail> stepContainerConfigurationDetails;
    /**
     * @return The configuration details of a Dataflow step.
     * 
     */
    private List<GetPipelineRunsPipelineRunStepOverrideDetailStepDataflowConfigurationDetail> stepDataflowConfigurationDetails;
    /**
     * @return The name of the step.
     * 
     */
    private String stepName;

    private GetPipelineRunsPipelineRunStepOverrideDetail() {}
    /**
     * @return The configuration details of a step.
     * 
     */
    public List<GetPipelineRunsPipelineRunStepOverrideDetailStepConfigurationDetail> stepConfigurationDetails() {
        return this.stepConfigurationDetails;
    }
    /**
     * @return Container Details for a step in pipeline.
     * 
     */
    public List<GetPipelineRunsPipelineRunStepOverrideDetailStepContainerConfigurationDetail> stepContainerConfigurationDetails() {
        return this.stepContainerConfigurationDetails;
    }
    /**
     * @return The configuration details of a Dataflow step.
     * 
     */
    public List<GetPipelineRunsPipelineRunStepOverrideDetailStepDataflowConfigurationDetail> stepDataflowConfigurationDetails() {
        return this.stepDataflowConfigurationDetails;
    }
    /**
     * @return The name of the step.
     * 
     */
    public String stepName() {
        return this.stepName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPipelineRunsPipelineRunStepOverrideDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetPipelineRunsPipelineRunStepOverrideDetailStepConfigurationDetail> stepConfigurationDetails;
        private List<GetPipelineRunsPipelineRunStepOverrideDetailStepContainerConfigurationDetail> stepContainerConfigurationDetails;
        private List<GetPipelineRunsPipelineRunStepOverrideDetailStepDataflowConfigurationDetail> stepDataflowConfigurationDetails;
        private String stepName;
        public Builder() {}
        public Builder(GetPipelineRunsPipelineRunStepOverrideDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.stepConfigurationDetails = defaults.stepConfigurationDetails;
    	      this.stepContainerConfigurationDetails = defaults.stepContainerConfigurationDetails;
    	      this.stepDataflowConfigurationDetails = defaults.stepDataflowConfigurationDetails;
    	      this.stepName = defaults.stepName;
        }

        @CustomType.Setter
        public Builder stepConfigurationDetails(List<GetPipelineRunsPipelineRunStepOverrideDetailStepConfigurationDetail> stepConfigurationDetails) {
            if (stepConfigurationDetails == null) {
              throw new MissingRequiredPropertyException("GetPipelineRunsPipelineRunStepOverrideDetail", "stepConfigurationDetails");
            }
            this.stepConfigurationDetails = stepConfigurationDetails;
            return this;
        }
        public Builder stepConfigurationDetails(GetPipelineRunsPipelineRunStepOverrideDetailStepConfigurationDetail... stepConfigurationDetails) {
            return stepConfigurationDetails(List.of(stepConfigurationDetails));
        }
        @CustomType.Setter
        public Builder stepContainerConfigurationDetails(List<GetPipelineRunsPipelineRunStepOverrideDetailStepContainerConfigurationDetail> stepContainerConfigurationDetails) {
            if (stepContainerConfigurationDetails == null) {
              throw new MissingRequiredPropertyException("GetPipelineRunsPipelineRunStepOverrideDetail", "stepContainerConfigurationDetails");
            }
            this.stepContainerConfigurationDetails = stepContainerConfigurationDetails;
            return this;
        }
        public Builder stepContainerConfigurationDetails(GetPipelineRunsPipelineRunStepOverrideDetailStepContainerConfigurationDetail... stepContainerConfigurationDetails) {
            return stepContainerConfigurationDetails(List.of(stepContainerConfigurationDetails));
        }
        @CustomType.Setter
        public Builder stepDataflowConfigurationDetails(List<GetPipelineRunsPipelineRunStepOverrideDetailStepDataflowConfigurationDetail> stepDataflowConfigurationDetails) {
            if (stepDataflowConfigurationDetails == null) {
              throw new MissingRequiredPropertyException("GetPipelineRunsPipelineRunStepOverrideDetail", "stepDataflowConfigurationDetails");
            }
            this.stepDataflowConfigurationDetails = stepDataflowConfigurationDetails;
            return this;
        }
        public Builder stepDataflowConfigurationDetails(GetPipelineRunsPipelineRunStepOverrideDetailStepDataflowConfigurationDetail... stepDataflowConfigurationDetails) {
            return stepDataflowConfigurationDetails(List.of(stepDataflowConfigurationDetails));
        }
        @CustomType.Setter
        public Builder stepName(String stepName) {
            if (stepName == null) {
              throw new MissingRequiredPropertyException("GetPipelineRunsPipelineRunStepOverrideDetail", "stepName");
            }
            this.stepName = stepName;
            return this;
        }
        public GetPipelineRunsPipelineRunStepOverrideDetail build() {
            final var _resultValue = new GetPipelineRunsPipelineRunStepOverrideDetail();
            _resultValue.stepConfigurationDetails = stepConfigurationDetails;
            _resultValue.stepContainerConfigurationDetails = stepContainerConfigurationDetails;
            _resultValue.stepDataflowConfigurationDetails = stepDataflowConfigurationDetails;
            _resultValue.stepName = stepName;
            return _resultValue;
        }
    }
}
