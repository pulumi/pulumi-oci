// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataScience.outputs.ScheduleActionActionDetailsCreateJobRunDetails;
import com.pulumi.oci.DataScience.outputs.ScheduleActionActionDetailsCreatePipelineRunDetails;
import com.pulumi.oci.DataScience.outputs.ScheduleActionActionDetailsTriggerMlApplicationInstanceViewFlowDetails;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ScheduleActionActionDetails {
    /**
     * @return (Updatable) Parameters needed to create a new job run.
     * 
     */
    private @Nullable ScheduleActionActionDetailsCreateJobRunDetails createJobRunDetails;
    /**
     * @return (Updatable) The information about new PipelineRun.
     * 
     */
    private @Nullable ScheduleActionActionDetailsCreatePipelineRunDetails createPipelineRunDetails;
    /**
     * @return (Updatable) The type of http action to trigger.
     * 
     */
    private String httpActionType;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the schedule.
     * 
     */
    private @Nullable String mlApplicationInstanceViewId;
    /**
     * @return (Updatable) Payload for trigger request endpoint
     * 
     */
    private @Nullable ScheduleActionActionDetailsTriggerMlApplicationInstanceViewFlowDetails triggerMlApplicationInstanceViewFlowDetails;

    private ScheduleActionActionDetails() {}
    /**
     * @return (Updatable) Parameters needed to create a new job run.
     * 
     */
    public Optional<ScheduleActionActionDetailsCreateJobRunDetails> createJobRunDetails() {
        return Optional.ofNullable(this.createJobRunDetails);
    }
    /**
     * @return (Updatable) The information about new PipelineRun.
     * 
     */
    public Optional<ScheduleActionActionDetailsCreatePipelineRunDetails> createPipelineRunDetails() {
        return Optional.ofNullable(this.createPipelineRunDetails);
    }
    /**
     * @return (Updatable) The type of http action to trigger.
     * 
     */
    public String httpActionType() {
        return this.httpActionType;
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the schedule.
     * 
     */
    public Optional<String> mlApplicationInstanceViewId() {
        return Optional.ofNullable(this.mlApplicationInstanceViewId);
    }
    /**
     * @return (Updatable) Payload for trigger request endpoint
     * 
     */
    public Optional<ScheduleActionActionDetailsTriggerMlApplicationInstanceViewFlowDetails> triggerMlApplicationInstanceViewFlowDetails() {
        return Optional.ofNullable(this.triggerMlApplicationInstanceViewFlowDetails);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ScheduleActionActionDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable ScheduleActionActionDetailsCreateJobRunDetails createJobRunDetails;
        private @Nullable ScheduleActionActionDetailsCreatePipelineRunDetails createPipelineRunDetails;
        private String httpActionType;
        private @Nullable String mlApplicationInstanceViewId;
        private @Nullable ScheduleActionActionDetailsTriggerMlApplicationInstanceViewFlowDetails triggerMlApplicationInstanceViewFlowDetails;
        public Builder() {}
        public Builder(ScheduleActionActionDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.createJobRunDetails = defaults.createJobRunDetails;
    	      this.createPipelineRunDetails = defaults.createPipelineRunDetails;
    	      this.httpActionType = defaults.httpActionType;
    	      this.mlApplicationInstanceViewId = defaults.mlApplicationInstanceViewId;
    	      this.triggerMlApplicationInstanceViewFlowDetails = defaults.triggerMlApplicationInstanceViewFlowDetails;
        }

        @CustomType.Setter
        public Builder createJobRunDetails(@Nullable ScheduleActionActionDetailsCreateJobRunDetails createJobRunDetails) {

            this.createJobRunDetails = createJobRunDetails;
            return this;
        }
        @CustomType.Setter
        public Builder createPipelineRunDetails(@Nullable ScheduleActionActionDetailsCreatePipelineRunDetails createPipelineRunDetails) {

            this.createPipelineRunDetails = createPipelineRunDetails;
            return this;
        }
        @CustomType.Setter
        public Builder httpActionType(String httpActionType) {
            if (httpActionType == null) {
              throw new MissingRequiredPropertyException("ScheduleActionActionDetails", "httpActionType");
            }
            this.httpActionType = httpActionType;
            return this;
        }
        @CustomType.Setter
        public Builder mlApplicationInstanceViewId(@Nullable String mlApplicationInstanceViewId) {

            this.mlApplicationInstanceViewId = mlApplicationInstanceViewId;
            return this;
        }
        @CustomType.Setter
        public Builder triggerMlApplicationInstanceViewFlowDetails(@Nullable ScheduleActionActionDetailsTriggerMlApplicationInstanceViewFlowDetails triggerMlApplicationInstanceViewFlowDetails) {

            this.triggerMlApplicationInstanceViewFlowDetails = triggerMlApplicationInstanceViewFlowDetails;
            return this;
        }
        public ScheduleActionActionDetails build() {
            final var _resultValue = new ScheduleActionActionDetails();
            _resultValue.createJobRunDetails = createJobRunDetails;
            _resultValue.createPipelineRunDetails = createPipelineRunDetails;
            _resultValue.httpActionType = httpActionType;
            _resultValue.mlApplicationInstanceViewId = mlApplicationInstanceViewId;
            _resultValue.triggerMlApplicationInstanceViewFlowDetails = triggerMlApplicationInstanceViewFlowDetails;
            return _resultValue;
        }
    }
}
