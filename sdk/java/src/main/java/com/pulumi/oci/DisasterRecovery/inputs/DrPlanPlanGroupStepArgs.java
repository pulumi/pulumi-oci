// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DisasterRecovery.inputs.DrPlanPlanGroupStepUserDefinedStepArgs;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DrPlanPlanGroupStepArgs extends com.pulumi.resources.ResourceArgs {

    public static final DrPlanPlanGroupStepArgs Empty = new DrPlanPlanGroupStepArgs();

    /**
     * (Updatable) The display name of the DR Plan being created.  Example: `EBS Switchover PHX to IAD`
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) The display name of the DR Plan being created.  Example: `EBS Switchover PHX to IAD`
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The error mode for this step.
     * 
     */
    @Import(name="errorMode")
    private @Nullable Output<String> errorMode;

    /**
     * @return The error mode for this step.
     * 
     */
    public Optional<Output<String>> errorMode() {
        return Optional.ofNullable(this.errorMode);
    }

    /**
     * The unique id of the group to which this step belongs. Must not be modified by user.  Example: `sgid1.group..examplegroupsgid`
     * 
     */
    @Import(name="groupId")
    private @Nullable Output<String> groupId;

    /**
     * @return The unique id of the group to which this step belongs. Must not be modified by user.  Example: `sgid1.group..examplegroupsgid`
     * 
     */
    public Optional<Output<String>> groupId() {
        return Optional.ofNullable(this.groupId);
    }

    /**
     * The unique id of this step. Must not be modified by the user.  Example: `sgid1.step..examplestepsgid`
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return The unique id of this step. Must not be modified by the user.  Example: `sgid1.step..examplestepsgid`
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * A flag indicating whether this step should be enabled for execution.  Example: `true`
     * 
     */
    @Import(name="isEnabled")
    private @Nullable Output<Boolean> isEnabled;

    /**
     * @return A flag indicating whether this step should be enabled for execution.  Example: `true`
     * 
     */
    public Optional<Output<Boolean>> isEnabled() {
        return Optional.ofNullable(this.isEnabled);
    }

    /**
     * The OCID of the member associated with this step.  Example: `ocid1.database.oc1.phx.exampleocid1`
     * 
     */
    @Import(name="memberId")
    private @Nullable Output<String> memberId;

    /**
     * @return The OCID of the member associated with this step.  Example: `ocid1.database.oc1.phx.exampleocid1`
     * 
     */
    public Optional<Output<String>> memberId() {
        return Optional.ofNullable(this.memberId);
    }

    /**
     * The timeout in seconds for executing this step.  Example: `600`
     * 
     */
    @Import(name="timeout")
    private @Nullable Output<Integer> timeout;

    /**
     * @return The timeout in seconds for executing this step.  Example: `600`
     * 
     */
    public Optional<Output<Integer>> timeout() {
        return Optional.ofNullable(this.timeout);
    }

    /**
     * The type of DR Plan to be created.
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return The type of DR Plan to be created.
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    /**
     * The details for a user-defined step in a DR Plan.
     * 
     */
    @Import(name="userDefinedSteps")
    private @Nullable Output<List<DrPlanPlanGroupStepUserDefinedStepArgs>> userDefinedSteps;

    /**
     * @return The details for a user-defined step in a DR Plan.
     * 
     */
    public Optional<Output<List<DrPlanPlanGroupStepUserDefinedStepArgs>>> userDefinedSteps() {
        return Optional.ofNullable(this.userDefinedSteps);
    }

    private DrPlanPlanGroupStepArgs() {}

    private DrPlanPlanGroupStepArgs(DrPlanPlanGroupStepArgs $) {
        this.displayName = $.displayName;
        this.errorMode = $.errorMode;
        this.groupId = $.groupId;
        this.id = $.id;
        this.isEnabled = $.isEnabled;
        this.memberId = $.memberId;
        this.timeout = $.timeout;
        this.type = $.type;
        this.userDefinedSteps = $.userDefinedSteps;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DrPlanPlanGroupStepArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DrPlanPlanGroupStepArgs $;

        public Builder() {
            $ = new DrPlanPlanGroupStepArgs();
        }

        public Builder(DrPlanPlanGroupStepArgs defaults) {
            $ = new DrPlanPlanGroupStepArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param displayName (Updatable) The display name of the DR Plan being created.  Example: `EBS Switchover PHX to IAD`
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The display name of the DR Plan being created.  Example: `EBS Switchover PHX to IAD`
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param errorMode The error mode for this step.
         * 
         * @return builder
         * 
         */
        public Builder errorMode(@Nullable Output<String> errorMode) {
            $.errorMode = errorMode;
            return this;
        }

        /**
         * @param errorMode The error mode for this step.
         * 
         * @return builder
         * 
         */
        public Builder errorMode(String errorMode) {
            return errorMode(Output.of(errorMode));
        }

        /**
         * @param groupId The unique id of the group to which this step belongs. Must not be modified by user.  Example: `sgid1.group..examplegroupsgid`
         * 
         * @return builder
         * 
         */
        public Builder groupId(@Nullable Output<String> groupId) {
            $.groupId = groupId;
            return this;
        }

        /**
         * @param groupId The unique id of the group to which this step belongs. Must not be modified by user.  Example: `sgid1.group..examplegroupsgid`
         * 
         * @return builder
         * 
         */
        public Builder groupId(String groupId) {
            return groupId(Output.of(groupId));
        }

        /**
         * @param id The unique id of this step. Must not be modified by the user.  Example: `sgid1.step..examplestepsgid`
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id The unique id of this step. Must not be modified by the user.  Example: `sgid1.step..examplestepsgid`
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param isEnabled A flag indicating whether this step should be enabled for execution.  Example: `true`
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(@Nullable Output<Boolean> isEnabled) {
            $.isEnabled = isEnabled;
            return this;
        }

        /**
         * @param isEnabled A flag indicating whether this step should be enabled for execution.  Example: `true`
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(Boolean isEnabled) {
            return isEnabled(Output.of(isEnabled));
        }

        /**
         * @param memberId The OCID of the member associated with this step.  Example: `ocid1.database.oc1.phx.exampleocid1`
         * 
         * @return builder
         * 
         */
        public Builder memberId(@Nullable Output<String> memberId) {
            $.memberId = memberId;
            return this;
        }

        /**
         * @param memberId The OCID of the member associated with this step.  Example: `ocid1.database.oc1.phx.exampleocid1`
         * 
         * @return builder
         * 
         */
        public Builder memberId(String memberId) {
            return memberId(Output.of(memberId));
        }

        /**
         * @param timeout The timeout in seconds for executing this step.  Example: `600`
         * 
         * @return builder
         * 
         */
        public Builder timeout(@Nullable Output<Integer> timeout) {
            $.timeout = timeout;
            return this;
        }

        /**
         * @param timeout The timeout in seconds for executing this step.  Example: `600`
         * 
         * @return builder
         * 
         */
        public Builder timeout(Integer timeout) {
            return timeout(Output.of(timeout));
        }

        /**
         * @param type The type of DR Plan to be created.
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type The type of DR Plan to be created.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        /**
         * @param userDefinedSteps The details for a user-defined step in a DR Plan.
         * 
         * @return builder
         * 
         */
        public Builder userDefinedSteps(@Nullable Output<List<DrPlanPlanGroupStepUserDefinedStepArgs>> userDefinedSteps) {
            $.userDefinedSteps = userDefinedSteps;
            return this;
        }

        /**
         * @param userDefinedSteps The details for a user-defined step in a DR Plan.
         * 
         * @return builder
         * 
         */
        public Builder userDefinedSteps(List<DrPlanPlanGroupStepUserDefinedStepArgs> userDefinedSteps) {
            return userDefinedSteps(Output.of(userDefinedSteps));
        }

        /**
         * @param userDefinedSteps The details for a user-defined step in a DR Plan.
         * 
         * @return builder
         * 
         */
        public Builder userDefinedSteps(DrPlanPlanGroupStepUserDefinedStepArgs... userDefinedSteps) {
            return userDefinedSteps(List.of(userDefinedSteps));
        }

        public DrPlanPlanGroupStepArgs build() {
            return $;
        }
    }

}