// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Autoscaling.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Autoscaling.inputs.AutoScalingConfigurationPolicyRuleActionArgs;
import com.pulumi.oci.Autoscaling.inputs.AutoScalingConfigurationPolicyRuleMetricArgs;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AutoScalingConfigurationPolicyRuleArgs extends com.pulumi.resources.ResourceArgs {

    public static final AutoScalingConfigurationPolicyRuleArgs Empty = new AutoScalingConfigurationPolicyRuleArgs();

    /**
     * The action to take when autoscaling is triggered.
     * 
     */
    @Import(name="action")
    private @Nullable Output<AutoScalingConfigurationPolicyRuleActionArgs> action;

    /**
     * @return The action to take when autoscaling is triggered.
     * 
     */
    public Optional<Output<AutoScalingConfigurationPolicyRuleActionArgs>> action() {
        return Optional.ofNullable(this.action);
    }

    @Import(name="displayName", required=true)
    private Output<String> displayName;

    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * ID of the condition that is assigned after creation.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return ID of the condition that is assigned after creation.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * Metric and threshold details for triggering an autoscaling action.
     * 
     */
    @Import(name="metric")
    private @Nullable Output<AutoScalingConfigurationPolicyRuleMetricArgs> metric;

    /**
     * @return Metric and threshold details for triggering an autoscaling action.
     * 
     */
    public Optional<Output<AutoScalingConfigurationPolicyRuleMetricArgs>> metric() {
        return Optional.ofNullable(this.metric);
    }

    private AutoScalingConfigurationPolicyRuleArgs() {}

    private AutoScalingConfigurationPolicyRuleArgs(AutoScalingConfigurationPolicyRuleArgs $) {
        this.action = $.action;
        this.displayName = $.displayName;
        this.id = $.id;
        this.metric = $.metric;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AutoScalingConfigurationPolicyRuleArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AutoScalingConfigurationPolicyRuleArgs $;

        public Builder() {
            $ = new AutoScalingConfigurationPolicyRuleArgs();
        }

        public Builder(AutoScalingConfigurationPolicyRuleArgs defaults) {
            $ = new AutoScalingConfigurationPolicyRuleArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param action The action to take when autoscaling is triggered.
         * 
         * @return builder
         * 
         */
        public Builder action(@Nullable Output<AutoScalingConfigurationPolicyRuleActionArgs> action) {
            $.action = action;
            return this;
        }

        /**
         * @param action The action to take when autoscaling is triggered.
         * 
         * @return builder
         * 
         */
        public Builder action(AutoScalingConfigurationPolicyRuleActionArgs action) {
            return action(Output.of(action));
        }

        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param id ID of the condition that is assigned after creation.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id ID of the condition that is assigned after creation.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param metric Metric and threshold details for triggering an autoscaling action.
         * 
         * @return builder
         * 
         */
        public Builder metric(@Nullable Output<AutoScalingConfigurationPolicyRuleMetricArgs> metric) {
            $.metric = metric;
            return this;
        }

        /**
         * @param metric Metric and threshold details for triggering an autoscaling action.
         * 
         * @return builder
         * 
         */
        public Builder metric(AutoScalingConfigurationPolicyRuleMetricArgs metric) {
            return metric(Output.of(metric));
        }

        public AutoScalingConfigurationPolicyRuleArgs build() {
            if ($.displayName == null) {
                throw new MissingRequiredPropertyException("AutoScalingConfigurationPolicyRuleArgs", "displayName");
            }
            return $;
        }
    }

}
