// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DisasterRecovery.outputs.GetDrPlanExecutionGroupExecutionStepExecutionLogLocation;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDrPlanExecutionGroupExecutionStepExecution {
    /**
     * @return The display name of the step.  Example: `DATABASE_SWITCHOVER`
     * 
     */
    private String displayName;
    /**
     * @return The total duration in seconds taken to complete step execution.  Example: `35`
     * 
     */
    private Integer executionDurationInSec;
    /**
     * @return The unique id of the group to which this step belongs. Must not be modified by user.  Example: `sgid1.group..examplegroupsgid`
     * 
     */
    private String groupId;
    /**
     * @return Information about an Object Storage log location for a DR Protection Group.
     * 
     */
    private List<GetDrPlanExecutionGroupExecutionStepExecutionLogLocation> logLocations;
    /**
     * @return The status of the step execution.
     * 
     */
    private String status;
    /**
     * @return Additional details about the step execution status.  Example: `This step failed to complete due to a timeout`
     * 
     */
    private String statusDetails;
    /**
     * @return The unique id of this step. Must not be modified by user.  Example: `sgid1.step..examplestepsgid`
     * 
     */
    private String stepId;
    /**
     * @return The date and time at which DR Plan Execution succeeded, failed, was paused, or was canceled. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    private String timeEnded;
    /**
     * @return The date and time at which DR Plan Execution began. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    private String timeStarted;
    /**
     * @return The plan group type.
     * 
     */
    private String type;

    private GetDrPlanExecutionGroupExecutionStepExecution() {}
    /**
     * @return The display name of the step.  Example: `DATABASE_SWITCHOVER`
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The total duration in seconds taken to complete step execution.  Example: `35`
     * 
     */
    public Integer executionDurationInSec() {
        return this.executionDurationInSec;
    }
    /**
     * @return The unique id of the group to which this step belongs. Must not be modified by user.  Example: `sgid1.group..examplegroupsgid`
     * 
     */
    public String groupId() {
        return this.groupId;
    }
    /**
     * @return Information about an Object Storage log location for a DR Protection Group.
     * 
     */
    public List<GetDrPlanExecutionGroupExecutionStepExecutionLogLocation> logLocations() {
        return this.logLocations;
    }
    /**
     * @return The status of the step execution.
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return Additional details about the step execution status.  Example: `This step failed to complete due to a timeout`
     * 
     */
    public String statusDetails() {
        return this.statusDetails;
    }
    /**
     * @return The unique id of this step. Must not be modified by user.  Example: `sgid1.step..examplestepsgid`
     * 
     */
    public String stepId() {
        return this.stepId;
    }
    /**
     * @return The date and time at which DR Plan Execution succeeded, failed, was paused, or was canceled. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    public String timeEnded() {
        return this.timeEnded;
    }
    /**
     * @return The date and time at which DR Plan Execution began. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    public String timeStarted() {
        return this.timeStarted;
    }
    /**
     * @return The plan group type.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDrPlanExecutionGroupExecutionStepExecution defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String displayName;
        private Integer executionDurationInSec;
        private String groupId;
        private List<GetDrPlanExecutionGroupExecutionStepExecutionLogLocation> logLocations;
        private String status;
        private String statusDetails;
        private String stepId;
        private String timeEnded;
        private String timeStarted;
        private String type;
        public Builder() {}
        public Builder(GetDrPlanExecutionGroupExecutionStepExecution defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.executionDurationInSec = defaults.executionDurationInSec;
    	      this.groupId = defaults.groupId;
    	      this.logLocations = defaults.logLocations;
    	      this.status = defaults.status;
    	      this.statusDetails = defaults.statusDetails;
    	      this.stepId = defaults.stepId;
    	      this.timeEnded = defaults.timeEnded;
    	      this.timeStarted = defaults.timeStarted;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder executionDurationInSec(Integer executionDurationInSec) {
            this.executionDurationInSec = Objects.requireNonNull(executionDurationInSec);
            return this;
        }
        @CustomType.Setter
        public Builder groupId(String groupId) {
            this.groupId = Objects.requireNonNull(groupId);
            return this;
        }
        @CustomType.Setter
        public Builder logLocations(List<GetDrPlanExecutionGroupExecutionStepExecutionLogLocation> logLocations) {
            this.logLocations = Objects.requireNonNull(logLocations);
            return this;
        }
        public Builder logLocations(GetDrPlanExecutionGroupExecutionStepExecutionLogLocation... logLocations) {
            return logLocations(List.of(logLocations));
        }
        @CustomType.Setter
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        @CustomType.Setter
        public Builder statusDetails(String statusDetails) {
            this.statusDetails = Objects.requireNonNull(statusDetails);
            return this;
        }
        @CustomType.Setter
        public Builder stepId(String stepId) {
            this.stepId = Objects.requireNonNull(stepId);
            return this;
        }
        @CustomType.Setter
        public Builder timeEnded(String timeEnded) {
            this.timeEnded = Objects.requireNonNull(timeEnded);
            return this;
        }
        @CustomType.Setter
        public Builder timeStarted(String timeStarted) {
            this.timeStarted = Objects.requireNonNull(timeStarted);
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public GetDrPlanExecutionGroupExecutionStepExecution build() {
            final var o = new GetDrPlanExecutionGroupExecutionStepExecution();
            o.displayName = displayName;
            o.executionDurationInSec = executionDurationInSec;
            o.groupId = groupId;
            o.logLocations = logLocations;
            o.status = status;
            o.statusDetails = statusDetails;
            o.stepId = stepId;
            o.timeEnded = timeEnded;
            o.timeStarted = timeStarted;
            o.type = type;
            return o;
        }
    }
}