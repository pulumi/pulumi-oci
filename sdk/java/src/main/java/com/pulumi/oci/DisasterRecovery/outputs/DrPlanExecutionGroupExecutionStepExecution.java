// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DisasterRecovery.outputs.DrPlanExecutionGroupExecutionStepExecutionLogLocation;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DrPlanExecutionGroupExecutionStepExecution {
    /**
     * @return (Updatable) The display name of the DR Plan Execution.  Example: `Execution - EBS Switchover PHX to IAD`
     * 
     */
    private @Nullable String displayName;
    /**
     * @return The total duration in seconds taken to complete step execution.  Example: `35`
     * 
     */
    private @Nullable Integer executionDurationInSec;
    /**
     * @return The unique id of the group to which this step belongs. Must not be modified by user.  Example: `sgid1.group..examplegroupsgid`
     * 
     */
    private @Nullable String groupId;
    /**
     * @return Information about an Object Storage log location for a DR Protection Group.
     * 
     */
    private @Nullable List<DrPlanExecutionGroupExecutionStepExecutionLogLocation> logLocations;
    /**
     * @return The status of the step execution.
     * 
     */
    private @Nullable String status;
    /**
     * @return Additional details about the step execution status.  Example: `This step failed to complete due to a timeout`
     * 
     */
    private @Nullable String statusDetails;
    /**
     * @return The unique id of this step. Must not be modified by user.  Example: `sgid1.step..examplestepsgid`
     * 
     */
    private @Nullable String stepId;
    /**
     * @return The date and time at which DR Plan Execution succeeded, failed, was paused, or was canceled. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    private @Nullable String timeEnded;
    /**
     * @return The date and time at which DR Plan Execution began. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    private @Nullable String timeStarted;
    /**
     * @return The plan group type.
     * 
     */
    private @Nullable String type;

    private DrPlanExecutionGroupExecutionStepExecution() {}
    /**
     * @return (Updatable) The display name of the DR Plan Execution.  Example: `Execution - EBS Switchover PHX to IAD`
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return The total duration in seconds taken to complete step execution.  Example: `35`
     * 
     */
    public Optional<Integer> executionDurationInSec() {
        return Optional.ofNullable(this.executionDurationInSec);
    }
    /**
     * @return The unique id of the group to which this step belongs. Must not be modified by user.  Example: `sgid1.group..examplegroupsgid`
     * 
     */
    public Optional<String> groupId() {
        return Optional.ofNullable(this.groupId);
    }
    /**
     * @return Information about an Object Storage log location for a DR Protection Group.
     * 
     */
    public List<DrPlanExecutionGroupExecutionStepExecutionLogLocation> logLocations() {
        return this.logLocations == null ? List.of() : this.logLocations;
    }
    /**
     * @return The status of the step execution.
     * 
     */
    public Optional<String> status() {
        return Optional.ofNullable(this.status);
    }
    /**
     * @return Additional details about the step execution status.  Example: `This step failed to complete due to a timeout`
     * 
     */
    public Optional<String> statusDetails() {
        return Optional.ofNullable(this.statusDetails);
    }
    /**
     * @return The unique id of this step. Must not be modified by user.  Example: `sgid1.step..examplestepsgid`
     * 
     */
    public Optional<String> stepId() {
        return Optional.ofNullable(this.stepId);
    }
    /**
     * @return The date and time at which DR Plan Execution succeeded, failed, was paused, or was canceled. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    public Optional<String> timeEnded() {
        return Optional.ofNullable(this.timeEnded);
    }
    /**
     * @return The date and time at which DR Plan Execution began. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    public Optional<String> timeStarted() {
        return Optional.ofNullable(this.timeStarted);
    }
    /**
     * @return The plan group type.
     * 
     */
    public Optional<String> type() {
        return Optional.ofNullable(this.type);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DrPlanExecutionGroupExecutionStepExecution defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String displayName;
        private @Nullable Integer executionDurationInSec;
        private @Nullable String groupId;
        private @Nullable List<DrPlanExecutionGroupExecutionStepExecutionLogLocation> logLocations;
        private @Nullable String status;
        private @Nullable String statusDetails;
        private @Nullable String stepId;
        private @Nullable String timeEnded;
        private @Nullable String timeStarted;
        private @Nullable String type;
        public Builder() {}
        public Builder(DrPlanExecutionGroupExecutionStepExecution defaults) {
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
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder executionDurationInSec(@Nullable Integer executionDurationInSec) {
            this.executionDurationInSec = executionDurationInSec;
            return this;
        }
        @CustomType.Setter
        public Builder groupId(@Nullable String groupId) {
            this.groupId = groupId;
            return this;
        }
        @CustomType.Setter
        public Builder logLocations(@Nullable List<DrPlanExecutionGroupExecutionStepExecutionLogLocation> logLocations) {
            this.logLocations = logLocations;
            return this;
        }
        public Builder logLocations(DrPlanExecutionGroupExecutionStepExecutionLogLocation... logLocations) {
            return logLocations(List.of(logLocations));
        }
        @CustomType.Setter
        public Builder status(@Nullable String status) {
            this.status = status;
            return this;
        }
        @CustomType.Setter
        public Builder statusDetails(@Nullable String statusDetails) {
            this.statusDetails = statusDetails;
            return this;
        }
        @CustomType.Setter
        public Builder stepId(@Nullable String stepId) {
            this.stepId = stepId;
            return this;
        }
        @CustomType.Setter
        public Builder timeEnded(@Nullable String timeEnded) {
            this.timeEnded = timeEnded;
            return this;
        }
        @CustomType.Setter
        public Builder timeStarted(@Nullable String timeStarted) {
            this.timeStarted = timeStarted;
            return this;
        }
        @CustomType.Setter
        public Builder type(@Nullable String type) {
            this.type = type;
            return this;
        }
        public DrPlanExecutionGroupExecutionStepExecution build() {
            final var o = new DrPlanExecutionGroupExecutionStepExecution();
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