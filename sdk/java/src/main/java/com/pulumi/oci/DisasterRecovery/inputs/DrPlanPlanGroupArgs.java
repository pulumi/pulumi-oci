// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DisasterRecovery.inputs.DrPlanPlanGroupStepArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DrPlanPlanGroupArgs extends com.pulumi.resources.ResourceArgs {

    public static final DrPlanPlanGroupArgs Empty = new DrPlanPlanGroupArgs();

    /**
     * (Updatable) The display name of the DR plan being created.  Example: `EBS Switchover PHX to IAD`
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) The display name of the DR plan being created.  Example: `EBS Switchover PHX to IAD`
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The unique id of the step. Must not be modified by the user.  Example: `sgid1.step..uniqueID`
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return The unique id of the step. Must not be modified by the user.  Example: `sgid1.step..uniqueID`
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * A flag indicating whether this group should be enabled for execution. This flag is only applicable to the `USER_DEFINED_PAUSE` group. The flag should be null for the remaining group types.  Example: `true`
     * 
     */
    @Import(name="isPauseEnabled")
    private @Nullable Output<Boolean> isPauseEnabled;

    /**
     * @return A flag indicating whether this group should be enabled for execution. This flag is only applicable to the `USER_DEFINED_PAUSE` group. The flag should be null for the remaining group types.  Example: `true`
     * 
     */
    public Optional<Output<Boolean>> isPauseEnabled() {
        return Optional.ofNullable(this.isPauseEnabled);
    }

    /**
     * The DR plan step refresh status.  Example: `STEP_ADDED`
     * 
     */
    @Import(name="refreshStatus")
    private @Nullable Output<String> refreshStatus;

    /**
     * @return The DR plan step refresh status.  Example: `STEP_ADDED`
     * 
     */
    public Optional<Output<String>> refreshStatus() {
        return Optional.ofNullable(this.refreshStatus);
    }

    /**
     * The list of steps in the group.
     * 
     */
    @Import(name="steps")
    private @Nullable Output<List<DrPlanPlanGroupStepArgs>> steps;

    /**
     * @return The list of steps in the group.
     * 
     */
    public Optional<Output<List<DrPlanPlanGroupStepArgs>>> steps() {
        return Optional.ofNullable(this.steps);
    }

    /**
     * The type of DR plan to be created.
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return The type of DR plan to be created.
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    private DrPlanPlanGroupArgs() {}

    private DrPlanPlanGroupArgs(DrPlanPlanGroupArgs $) {
        this.displayName = $.displayName;
        this.id = $.id;
        this.isPauseEnabled = $.isPauseEnabled;
        this.refreshStatus = $.refreshStatus;
        this.steps = $.steps;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DrPlanPlanGroupArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DrPlanPlanGroupArgs $;

        public Builder() {
            $ = new DrPlanPlanGroupArgs();
        }

        public Builder(DrPlanPlanGroupArgs defaults) {
            $ = new DrPlanPlanGroupArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param displayName (Updatable) The display name of the DR plan being created.  Example: `EBS Switchover PHX to IAD`
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The display name of the DR plan being created.  Example: `EBS Switchover PHX to IAD`
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param id The unique id of the step. Must not be modified by the user.  Example: `sgid1.step..uniqueID`
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id The unique id of the step. Must not be modified by the user.  Example: `sgid1.step..uniqueID`
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param isPauseEnabled A flag indicating whether this group should be enabled for execution. This flag is only applicable to the `USER_DEFINED_PAUSE` group. The flag should be null for the remaining group types.  Example: `true`
         * 
         * @return builder
         * 
         */
        public Builder isPauseEnabled(@Nullable Output<Boolean> isPauseEnabled) {
            $.isPauseEnabled = isPauseEnabled;
            return this;
        }

        /**
         * @param isPauseEnabled A flag indicating whether this group should be enabled for execution. This flag is only applicable to the `USER_DEFINED_PAUSE` group. The flag should be null for the remaining group types.  Example: `true`
         * 
         * @return builder
         * 
         */
        public Builder isPauseEnabled(Boolean isPauseEnabled) {
            return isPauseEnabled(Output.of(isPauseEnabled));
        }

        /**
         * @param refreshStatus The DR plan step refresh status.  Example: `STEP_ADDED`
         * 
         * @return builder
         * 
         */
        public Builder refreshStatus(@Nullable Output<String> refreshStatus) {
            $.refreshStatus = refreshStatus;
            return this;
        }

        /**
         * @param refreshStatus The DR plan step refresh status.  Example: `STEP_ADDED`
         * 
         * @return builder
         * 
         */
        public Builder refreshStatus(String refreshStatus) {
            return refreshStatus(Output.of(refreshStatus));
        }

        /**
         * @param steps The list of steps in the group.
         * 
         * @return builder
         * 
         */
        public Builder steps(@Nullable Output<List<DrPlanPlanGroupStepArgs>> steps) {
            $.steps = steps;
            return this;
        }

        /**
         * @param steps The list of steps in the group.
         * 
         * @return builder
         * 
         */
        public Builder steps(List<DrPlanPlanGroupStepArgs> steps) {
            return steps(Output.of(steps));
        }

        /**
         * @param steps The list of steps in the group.
         * 
         * @return builder
         * 
         */
        public Builder steps(DrPlanPlanGroupStepArgs... steps) {
            return steps(List.of(steps));
        }

        /**
         * @param type The type of DR plan to be created.
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type The type of DR plan to be created.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public DrPlanPlanGroupArgs build() {
            return $;
        }
    }

}
