// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.BigDataService.inputs.AutoScalingConfigurationPolicyDetailsScaleDownConfigArgs;
import com.pulumi.oci.BigDataService.inputs.AutoScalingConfigurationPolicyDetailsScaleInConfigArgs;
import com.pulumi.oci.BigDataService.inputs.AutoScalingConfigurationPolicyDetailsScaleOutConfigArgs;
import com.pulumi.oci.BigDataService.inputs.AutoScalingConfigurationPolicyDetailsScaleUpConfigArgs;
import com.pulumi.oci.BigDataService.inputs.AutoScalingConfigurationPolicyDetailsScheduleDetailArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AutoScalingConfigurationPolicyDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final AutoScalingConfigurationPolicyDetailsArgs Empty = new AutoScalingConfigurationPolicyDetailsArgs();

    /**
     * The type of autoscaling action to take.
     * 
     */
    @Import(name="actionType")
    private @Nullable Output<String> actionType;

    /**
     * @return The type of autoscaling action to take.
     * 
     */
    public Optional<Output<String>> actionType() {
        return Optional.ofNullable(this.actionType);
    }

    /**
     * Type of autoscaling policy.
     * 
     */
    @Import(name="policyType", required=true)
    private Output<String> policyType;

    /**
     * @return Type of autoscaling policy.
     * 
     */
    public Output<String> policyType() {
        return this.policyType;
    }

    /**
     * (Updatable) Configration for a metric based vertical scale-down policy.
     * 
     */
    @Import(name="scaleDownConfig")
    private @Nullable Output<AutoScalingConfigurationPolicyDetailsScaleDownConfigArgs> scaleDownConfig;

    /**
     * @return (Updatable) Configration for a metric based vertical scale-down policy.
     * 
     */
    public Optional<Output<AutoScalingConfigurationPolicyDetailsScaleDownConfigArgs>> scaleDownConfig() {
        return Optional.ofNullable(this.scaleDownConfig);
    }

    /**
     * (Updatable) Configration for a metric based horizontal scale-in policy.
     * 
     */
    @Import(name="scaleInConfig")
    private @Nullable Output<AutoScalingConfigurationPolicyDetailsScaleInConfigArgs> scaleInConfig;

    /**
     * @return (Updatable) Configration for a metric based horizontal scale-in policy.
     * 
     */
    public Optional<Output<AutoScalingConfigurationPolicyDetailsScaleInConfigArgs>> scaleInConfig() {
        return Optional.ofNullable(this.scaleInConfig);
    }

    /**
     * (Updatable) Configration for a metric based horizontal scale-out policy.
     * 
     */
    @Import(name="scaleOutConfig")
    private @Nullable Output<AutoScalingConfigurationPolicyDetailsScaleOutConfigArgs> scaleOutConfig;

    /**
     * @return (Updatable) Configration for a metric based horizontal scale-out policy.
     * 
     */
    public Optional<Output<AutoScalingConfigurationPolicyDetailsScaleOutConfigArgs>> scaleOutConfig() {
        return Optional.ofNullable(this.scaleOutConfig);
    }

    /**
     * (Updatable) Configration for a metric based vertical scale-up policy.
     * 
     */
    @Import(name="scaleUpConfig")
    private @Nullable Output<AutoScalingConfigurationPolicyDetailsScaleUpConfigArgs> scaleUpConfig;

    /**
     * @return (Updatable) Configration for a metric based vertical scale-up policy.
     * 
     */
    public Optional<Output<AutoScalingConfigurationPolicyDetailsScaleUpConfigArgs>> scaleUpConfig() {
        return Optional.ofNullable(this.scaleUpConfig);
    }

    /**
     * (Updatable)
     * 
     */
    @Import(name="scheduleDetails")
    private @Nullable Output<List<AutoScalingConfigurationPolicyDetailsScheduleDetailArgs>> scheduleDetails;

    /**
     * @return (Updatable)
     * 
     */
    public Optional<Output<List<AutoScalingConfigurationPolicyDetailsScheduleDetailArgs>>> scheduleDetails() {
        return Optional.ofNullable(this.scheduleDetails);
    }

    /**
     * (Updatable) The time zone of the execution schedule, in IANA time zone database name format
     * 
     */
    @Import(name="timezone")
    private @Nullable Output<String> timezone;

    /**
     * @return (Updatable) The time zone of the execution schedule, in IANA time zone database name format
     * 
     */
    public Optional<Output<String>> timezone() {
        return Optional.ofNullable(this.timezone);
    }

    /**
     * The type of autoscaling trigger.
     * 
     */
    @Import(name="triggerType")
    private @Nullable Output<String> triggerType;

    /**
     * @return The type of autoscaling trigger.
     * 
     */
    public Optional<Output<String>> triggerType() {
        return Optional.ofNullable(this.triggerType);
    }

    private AutoScalingConfigurationPolicyDetailsArgs() {}

    private AutoScalingConfigurationPolicyDetailsArgs(AutoScalingConfigurationPolicyDetailsArgs $) {
        this.actionType = $.actionType;
        this.policyType = $.policyType;
        this.scaleDownConfig = $.scaleDownConfig;
        this.scaleInConfig = $.scaleInConfig;
        this.scaleOutConfig = $.scaleOutConfig;
        this.scaleUpConfig = $.scaleUpConfig;
        this.scheduleDetails = $.scheduleDetails;
        this.timezone = $.timezone;
        this.triggerType = $.triggerType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AutoScalingConfigurationPolicyDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AutoScalingConfigurationPolicyDetailsArgs $;

        public Builder() {
            $ = new AutoScalingConfigurationPolicyDetailsArgs();
        }

        public Builder(AutoScalingConfigurationPolicyDetailsArgs defaults) {
            $ = new AutoScalingConfigurationPolicyDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param actionType The type of autoscaling action to take.
         * 
         * @return builder
         * 
         */
        public Builder actionType(@Nullable Output<String> actionType) {
            $.actionType = actionType;
            return this;
        }

        /**
         * @param actionType The type of autoscaling action to take.
         * 
         * @return builder
         * 
         */
        public Builder actionType(String actionType) {
            return actionType(Output.of(actionType));
        }

        /**
         * @param policyType Type of autoscaling policy.
         * 
         * @return builder
         * 
         */
        public Builder policyType(Output<String> policyType) {
            $.policyType = policyType;
            return this;
        }

        /**
         * @param policyType Type of autoscaling policy.
         * 
         * @return builder
         * 
         */
        public Builder policyType(String policyType) {
            return policyType(Output.of(policyType));
        }

        /**
         * @param scaleDownConfig (Updatable) Configration for a metric based vertical scale-down policy.
         * 
         * @return builder
         * 
         */
        public Builder scaleDownConfig(@Nullable Output<AutoScalingConfigurationPolicyDetailsScaleDownConfigArgs> scaleDownConfig) {
            $.scaleDownConfig = scaleDownConfig;
            return this;
        }

        /**
         * @param scaleDownConfig (Updatable) Configration for a metric based vertical scale-down policy.
         * 
         * @return builder
         * 
         */
        public Builder scaleDownConfig(AutoScalingConfigurationPolicyDetailsScaleDownConfigArgs scaleDownConfig) {
            return scaleDownConfig(Output.of(scaleDownConfig));
        }

        /**
         * @param scaleInConfig (Updatable) Configration for a metric based horizontal scale-in policy.
         * 
         * @return builder
         * 
         */
        public Builder scaleInConfig(@Nullable Output<AutoScalingConfigurationPolicyDetailsScaleInConfigArgs> scaleInConfig) {
            $.scaleInConfig = scaleInConfig;
            return this;
        }

        /**
         * @param scaleInConfig (Updatable) Configration for a metric based horizontal scale-in policy.
         * 
         * @return builder
         * 
         */
        public Builder scaleInConfig(AutoScalingConfigurationPolicyDetailsScaleInConfigArgs scaleInConfig) {
            return scaleInConfig(Output.of(scaleInConfig));
        }

        /**
         * @param scaleOutConfig (Updatable) Configration for a metric based horizontal scale-out policy.
         * 
         * @return builder
         * 
         */
        public Builder scaleOutConfig(@Nullable Output<AutoScalingConfigurationPolicyDetailsScaleOutConfigArgs> scaleOutConfig) {
            $.scaleOutConfig = scaleOutConfig;
            return this;
        }

        /**
         * @param scaleOutConfig (Updatable) Configration for a metric based horizontal scale-out policy.
         * 
         * @return builder
         * 
         */
        public Builder scaleOutConfig(AutoScalingConfigurationPolicyDetailsScaleOutConfigArgs scaleOutConfig) {
            return scaleOutConfig(Output.of(scaleOutConfig));
        }

        /**
         * @param scaleUpConfig (Updatable) Configration for a metric based vertical scale-up policy.
         * 
         * @return builder
         * 
         */
        public Builder scaleUpConfig(@Nullable Output<AutoScalingConfigurationPolicyDetailsScaleUpConfigArgs> scaleUpConfig) {
            $.scaleUpConfig = scaleUpConfig;
            return this;
        }

        /**
         * @param scaleUpConfig (Updatable) Configration for a metric based vertical scale-up policy.
         * 
         * @return builder
         * 
         */
        public Builder scaleUpConfig(AutoScalingConfigurationPolicyDetailsScaleUpConfigArgs scaleUpConfig) {
            return scaleUpConfig(Output.of(scaleUpConfig));
        }

        /**
         * @param scheduleDetails (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder scheduleDetails(@Nullable Output<List<AutoScalingConfigurationPolicyDetailsScheduleDetailArgs>> scheduleDetails) {
            $.scheduleDetails = scheduleDetails;
            return this;
        }

        /**
         * @param scheduleDetails (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder scheduleDetails(List<AutoScalingConfigurationPolicyDetailsScheduleDetailArgs> scheduleDetails) {
            return scheduleDetails(Output.of(scheduleDetails));
        }

        /**
         * @param scheduleDetails (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder scheduleDetails(AutoScalingConfigurationPolicyDetailsScheduleDetailArgs... scheduleDetails) {
            return scheduleDetails(List.of(scheduleDetails));
        }

        /**
         * @param timezone (Updatable) The time zone of the execution schedule, in IANA time zone database name format
         * 
         * @return builder
         * 
         */
        public Builder timezone(@Nullable Output<String> timezone) {
            $.timezone = timezone;
            return this;
        }

        /**
         * @param timezone (Updatable) The time zone of the execution schedule, in IANA time zone database name format
         * 
         * @return builder
         * 
         */
        public Builder timezone(String timezone) {
            return timezone(Output.of(timezone));
        }

        /**
         * @param triggerType The type of autoscaling trigger.
         * 
         * @return builder
         * 
         */
        public Builder triggerType(@Nullable Output<String> triggerType) {
            $.triggerType = triggerType;
            return this;
        }

        /**
         * @param triggerType The type of autoscaling trigger.
         * 
         * @return builder
         * 
         */
        public Builder triggerType(String triggerType) {
            return triggerType(Output.of(triggerType));
        }

        public AutoScalingConfigurationPolicyDetailsArgs build() {
            $.policyType = Objects.requireNonNull($.policyType, "expected parameter 'policyType' to be non-null");
            return $;
        }
    }

}