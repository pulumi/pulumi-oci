// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Autoscaling.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class AutoScalingConfigurationPolicyResourceActionArgs extends com.pulumi.resources.ResourceArgs {

    public static final AutoScalingConfigurationPolicyResourceActionArgs Empty = new AutoScalingConfigurationPolicyResourceActionArgs();

    /**
     * The action to take when autoscaling is triggered.
     * 
     */
    @Import(name="action", required=true)
    private Output<String> action;

    /**
     * @return The action to take when autoscaling is triggered.
     * 
     */
    public Output<String> action() {
        return this.action;
    }

    /**
     * The type of resource action.
     * 
     */
    @Import(name="actionType", required=true)
    private Output<String> actionType;

    /**
     * @return The type of resource action.
     * 
     */
    public Output<String> actionType() {
        return this.actionType;
    }

    private AutoScalingConfigurationPolicyResourceActionArgs() {}

    private AutoScalingConfigurationPolicyResourceActionArgs(AutoScalingConfigurationPolicyResourceActionArgs $) {
        this.action = $.action;
        this.actionType = $.actionType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AutoScalingConfigurationPolicyResourceActionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AutoScalingConfigurationPolicyResourceActionArgs $;

        public Builder() {
            $ = new AutoScalingConfigurationPolicyResourceActionArgs();
        }

        public Builder(AutoScalingConfigurationPolicyResourceActionArgs defaults) {
            $ = new AutoScalingConfigurationPolicyResourceActionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param action The action to take when autoscaling is triggered.
         * 
         * @return builder
         * 
         */
        public Builder action(Output<String> action) {
            $.action = action;
            return this;
        }

        /**
         * @param action The action to take when autoscaling is triggered.
         * 
         * @return builder
         * 
         */
        public Builder action(String action) {
            return action(Output.of(action));
        }

        /**
         * @param actionType The type of resource action.
         * 
         * @return builder
         * 
         */
        public Builder actionType(Output<String> actionType) {
            $.actionType = actionType;
            return this;
        }

        /**
         * @param actionType The type of resource action.
         * 
         * @return builder
         * 
         */
        public Builder actionType(String actionType) {
            return actionType(Output.of(actionType));
        }

        public AutoScalingConfigurationPolicyResourceActionArgs build() {
            $.action = Objects.requireNonNull($.action, "expected parameter 'action' to be non-null");
            $.actionType = Objects.requireNonNull($.actionType, "expected parameter 'actionType' to be non-null");
            return $;
        }
    }

}