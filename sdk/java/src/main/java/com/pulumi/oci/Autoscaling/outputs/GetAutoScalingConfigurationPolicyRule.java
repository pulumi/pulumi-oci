// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Autoscaling.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Autoscaling.outputs.GetAutoScalingConfigurationPolicyRuleAction;
import com.pulumi.oci.Autoscaling.outputs.GetAutoScalingConfigurationPolicyRuleMetric;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAutoScalingConfigurationPolicyRule {
    /**
     * @return The action to take when autoscaling is triggered.
     * 
     */
    private List<GetAutoScalingConfigurationPolicyRuleAction> actions;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private String displayName;
    /**
     * @return ID of the condition that is assigned after creation.
     * 
     */
    private String id;
    /**
     * @return Metric and threshold details for triggering an autoscaling action.
     * 
     */
    private List<GetAutoScalingConfigurationPolicyRuleMetric> metrics;

    private GetAutoScalingConfigurationPolicyRule() {}
    /**
     * @return The action to take when autoscaling is triggered.
     * 
     */
    public List<GetAutoScalingConfigurationPolicyRuleAction> actions() {
        return this.actions;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return ID of the condition that is assigned after creation.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Metric and threshold details for triggering an autoscaling action.
     * 
     */
    public List<GetAutoScalingConfigurationPolicyRuleMetric> metrics() {
        return this.metrics;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutoScalingConfigurationPolicyRule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetAutoScalingConfigurationPolicyRuleAction> actions;
        private String displayName;
        private String id;
        private List<GetAutoScalingConfigurationPolicyRuleMetric> metrics;
        public Builder() {}
        public Builder(GetAutoScalingConfigurationPolicyRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.actions = defaults.actions;
    	      this.displayName = defaults.displayName;
    	      this.id = defaults.id;
    	      this.metrics = defaults.metrics;
        }

        @CustomType.Setter
        public Builder actions(List<GetAutoScalingConfigurationPolicyRuleAction> actions) {
            this.actions = Objects.requireNonNull(actions);
            return this;
        }
        public Builder actions(GetAutoScalingConfigurationPolicyRuleAction... actions) {
            return actions(List.of(actions));
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder metrics(List<GetAutoScalingConfigurationPolicyRuleMetric> metrics) {
            this.metrics = Objects.requireNonNull(metrics);
            return this;
        }
        public Builder metrics(GetAutoScalingConfigurationPolicyRuleMetric... metrics) {
            return metrics(List.of(metrics));
        }
        public GetAutoScalingConfigurationPolicyRule build() {
            final var o = new GetAutoScalingConfigurationPolicyRule();
            o.actions = actions;
            o.displayName = displayName;
            o.id = id;
            o.metrics = metrics;
            return o;
        }
    }
}