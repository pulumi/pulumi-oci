// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DisasterRecovery.inputs.DrPlanExecutionGroupExecutionStepExecutionLogLocationArgs;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DrPlanExecutionGroupExecutionStepExecutionArgs extends com.pulumi.resources.ResourceArgs {

    public static final DrPlanExecutionGroupExecutionStepExecutionArgs Empty = new DrPlanExecutionGroupExecutionStepExecutionArgs();

    /**
     * (Updatable) The display name of the DR plan execution.  Example: `Execution - EBS Switchover PHX to IAD`
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) The display name of the DR plan execution.  Example: `Execution - EBS Switchover PHX to IAD`
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The total duration in seconds taken to complete the step execution.  Example: `35`
     * 
     */
    @Import(name="executionDurationInSec")
    private @Nullable Output<Integer> executionDurationInSec;

    /**
     * @return The total duration in seconds taken to complete the step execution.  Example: `35`
     * 
     */
    public Optional<Output<Integer>> executionDurationInSec() {
        return Optional.ofNullable(this.executionDurationInSec);
    }

    /**
     * The unique id of the group to which this step belongs. Must not be modified by user.  Example: `sgid1.group..uniqueID`
     * 
     */
    @Import(name="groupId")
    private @Nullable Output<String> groupId;

    /**
     * @return The unique id of the group to which this step belongs. Must not be modified by user.  Example: `sgid1.group..uniqueID`
     * 
     */
    public Optional<Output<String>> groupId() {
        return Optional.ofNullable(this.groupId);
    }

    /**
     * The details of an object storage log location for a DR protection group.
     * 
     */
    @Import(name="logLocations")
    private @Nullable Output<List<DrPlanExecutionGroupExecutionStepExecutionLogLocationArgs>> logLocations;

    /**
     * @return The details of an object storage log location for a DR protection group.
     * 
     */
    public Optional<Output<List<DrPlanExecutionGroupExecutionStepExecutionLogLocationArgs>>> logLocations() {
        return Optional.ofNullable(this.logLocations);
    }

    /**
     * The status of the step execution.
     * 
     */
    @Import(name="status")
    private @Nullable Output<String> status;

    /**
     * @return The status of the step execution.
     * 
     */
    public Optional<Output<String>> status() {
        return Optional.ofNullable(this.status);
    }

    /**
     * Additional details on the step execution status.  Example: `This step failed to complete due to a timeout`
     * 
     */
    @Import(name="statusDetails")
    private @Nullable Output<String> statusDetails;

    /**
     * @return Additional details on the step execution status.  Example: `This step failed to complete due to a timeout`
     * 
     */
    public Optional<Output<String>> statusDetails() {
        return Optional.ofNullable(this.statusDetails);
    }

    /**
     * The unique id of the step. Must not be modified by user.  Example: `sgid1.step..uniqueID`
     * 
     */
    @Import(name="stepId")
    private @Nullable Output<String> stepId;

    /**
     * @return The unique id of the step. Must not be modified by user.  Example: `sgid1.step..uniqueID`
     * 
     */
    public Optional<Output<String>> stepId() {
        return Optional.ofNullable(this.stepId);
    }

    /**
     * The date and time at which DR plan execution succeeded, failed, was paused, or was canceled. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    @Import(name="timeEnded")
    private @Nullable Output<String> timeEnded;

    /**
     * @return The date and time at which DR plan execution succeeded, failed, was paused, or was canceled. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    public Optional<Output<String>> timeEnded() {
        return Optional.ofNullable(this.timeEnded);
    }

    /**
     * The date and time at which DR plan execution began. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    @Import(name="timeStarted")
    private @Nullable Output<String> timeStarted;

    /**
     * @return The date and time at which DR plan execution began. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    public Optional<Output<String>> timeStarted() {
        return Optional.ofNullable(this.timeStarted);
    }

    /**
     * The group type.  Example: `BUILT_IN`
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return The group type.  Example: `BUILT_IN`
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    /**
     * The display name of the DR Plan step type.  Example: `Database Switchover`
     * 
     */
    @Import(name="typeDisplayName")
    private @Nullable Output<String> typeDisplayName;

    /**
     * @return The display name of the DR Plan step type.  Example: `Database Switchover`
     * 
     */
    public Optional<Output<String>> typeDisplayName() {
        return Optional.ofNullable(this.typeDisplayName);
    }

    private DrPlanExecutionGroupExecutionStepExecutionArgs() {}

    private DrPlanExecutionGroupExecutionStepExecutionArgs(DrPlanExecutionGroupExecutionStepExecutionArgs $) {
        this.displayName = $.displayName;
        this.executionDurationInSec = $.executionDurationInSec;
        this.groupId = $.groupId;
        this.logLocations = $.logLocations;
        this.status = $.status;
        this.statusDetails = $.statusDetails;
        this.stepId = $.stepId;
        this.timeEnded = $.timeEnded;
        this.timeStarted = $.timeStarted;
        this.type = $.type;
        this.typeDisplayName = $.typeDisplayName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DrPlanExecutionGroupExecutionStepExecutionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DrPlanExecutionGroupExecutionStepExecutionArgs $;

        public Builder() {
            $ = new DrPlanExecutionGroupExecutionStepExecutionArgs();
        }

        public Builder(DrPlanExecutionGroupExecutionStepExecutionArgs defaults) {
            $ = new DrPlanExecutionGroupExecutionStepExecutionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param displayName (Updatable) The display name of the DR plan execution.  Example: `Execution - EBS Switchover PHX to IAD`
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The display name of the DR plan execution.  Example: `Execution - EBS Switchover PHX to IAD`
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param executionDurationInSec The total duration in seconds taken to complete the step execution.  Example: `35`
         * 
         * @return builder
         * 
         */
        public Builder executionDurationInSec(@Nullable Output<Integer> executionDurationInSec) {
            $.executionDurationInSec = executionDurationInSec;
            return this;
        }

        /**
         * @param executionDurationInSec The total duration in seconds taken to complete the step execution.  Example: `35`
         * 
         * @return builder
         * 
         */
        public Builder executionDurationInSec(Integer executionDurationInSec) {
            return executionDurationInSec(Output.of(executionDurationInSec));
        }

        /**
         * @param groupId The unique id of the group to which this step belongs. Must not be modified by user.  Example: `sgid1.group..uniqueID`
         * 
         * @return builder
         * 
         */
        public Builder groupId(@Nullable Output<String> groupId) {
            $.groupId = groupId;
            return this;
        }

        /**
         * @param groupId The unique id of the group to which this step belongs. Must not be modified by user.  Example: `sgid1.group..uniqueID`
         * 
         * @return builder
         * 
         */
        public Builder groupId(String groupId) {
            return groupId(Output.of(groupId));
        }

        /**
         * @param logLocations The details of an object storage log location for a DR protection group.
         * 
         * @return builder
         * 
         */
        public Builder logLocations(@Nullable Output<List<DrPlanExecutionGroupExecutionStepExecutionLogLocationArgs>> logLocations) {
            $.logLocations = logLocations;
            return this;
        }

        /**
         * @param logLocations The details of an object storage log location for a DR protection group.
         * 
         * @return builder
         * 
         */
        public Builder logLocations(List<DrPlanExecutionGroupExecutionStepExecutionLogLocationArgs> logLocations) {
            return logLocations(Output.of(logLocations));
        }

        /**
         * @param logLocations The details of an object storage log location for a DR protection group.
         * 
         * @return builder
         * 
         */
        public Builder logLocations(DrPlanExecutionGroupExecutionStepExecutionLogLocationArgs... logLocations) {
            return logLocations(List.of(logLocations));
        }

        /**
         * @param status The status of the step execution.
         * 
         * @return builder
         * 
         */
        public Builder status(@Nullable Output<String> status) {
            $.status = status;
            return this;
        }

        /**
         * @param status The status of the step execution.
         * 
         * @return builder
         * 
         */
        public Builder status(String status) {
            return status(Output.of(status));
        }

        /**
         * @param statusDetails Additional details on the step execution status.  Example: `This step failed to complete due to a timeout`
         * 
         * @return builder
         * 
         */
        public Builder statusDetails(@Nullable Output<String> statusDetails) {
            $.statusDetails = statusDetails;
            return this;
        }

        /**
         * @param statusDetails Additional details on the step execution status.  Example: `This step failed to complete due to a timeout`
         * 
         * @return builder
         * 
         */
        public Builder statusDetails(String statusDetails) {
            return statusDetails(Output.of(statusDetails));
        }

        /**
         * @param stepId The unique id of the step. Must not be modified by user.  Example: `sgid1.step..uniqueID`
         * 
         * @return builder
         * 
         */
        public Builder stepId(@Nullable Output<String> stepId) {
            $.stepId = stepId;
            return this;
        }

        /**
         * @param stepId The unique id of the step. Must not be modified by user.  Example: `sgid1.step..uniqueID`
         * 
         * @return builder
         * 
         */
        public Builder stepId(String stepId) {
            return stepId(Output.of(stepId));
        }

        /**
         * @param timeEnded The date and time at which DR plan execution succeeded, failed, was paused, or was canceled. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
         * 
         * @return builder
         * 
         */
        public Builder timeEnded(@Nullable Output<String> timeEnded) {
            $.timeEnded = timeEnded;
            return this;
        }

        /**
         * @param timeEnded The date and time at which DR plan execution succeeded, failed, was paused, or was canceled. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
         * 
         * @return builder
         * 
         */
        public Builder timeEnded(String timeEnded) {
            return timeEnded(Output.of(timeEnded));
        }

        /**
         * @param timeStarted The date and time at which DR plan execution began. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
         * 
         * @return builder
         * 
         */
        public Builder timeStarted(@Nullable Output<String> timeStarted) {
            $.timeStarted = timeStarted;
            return this;
        }

        /**
         * @param timeStarted The date and time at which DR plan execution began. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
         * 
         * @return builder
         * 
         */
        public Builder timeStarted(String timeStarted) {
            return timeStarted(Output.of(timeStarted));
        }

        /**
         * @param type The group type.  Example: `BUILT_IN`
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type The group type.  Example: `BUILT_IN`
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        /**
         * @param typeDisplayName The display name of the DR Plan step type.  Example: `Database Switchover`
         * 
         * @return builder
         * 
         */
        public Builder typeDisplayName(@Nullable Output<String> typeDisplayName) {
            $.typeDisplayName = typeDisplayName;
            return this;
        }

        /**
         * @param typeDisplayName The display name of the DR Plan step type.  Example: `Database Switchover`
         * 
         * @return builder
         * 
         */
        public Builder typeDisplayName(String typeDisplayName) {
            return typeDisplayName(Output.of(typeDisplayName));
        }

        public DrPlanExecutionGroupExecutionStepExecutionArgs build() {
            return $;
        }
    }

}
