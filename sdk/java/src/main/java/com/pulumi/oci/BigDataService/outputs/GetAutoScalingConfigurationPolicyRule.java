// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.BigDataService.outputs.GetAutoScalingConfigurationPolicyRuleMetric;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAutoScalingConfigurationPolicyRule {
    /**
     * @return The valid value are CHANGE_SHAPE_SCALE_UP or CHANGE_SHAPE_SCALE_DOWN.
     * 
     */
    private String action;
    /**
     * @return Metric and threshold details for triggering an autoscale action.
     * 
     */
    private List<GetAutoScalingConfigurationPolicyRuleMetric> metrics;

    private GetAutoScalingConfigurationPolicyRule() {}
    /**
     * @return The valid value are CHANGE_SHAPE_SCALE_UP or CHANGE_SHAPE_SCALE_DOWN.
     * 
     */
    public String action() {
        return this.action;
    }
    /**
     * @return Metric and threshold details for triggering an autoscale action.
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
        private String action;
        private List<GetAutoScalingConfigurationPolicyRuleMetric> metrics;
        public Builder() {}
        public Builder(GetAutoScalingConfigurationPolicyRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.action = defaults.action;
    	      this.metrics = defaults.metrics;
        }

        @CustomType.Setter
        public Builder action(String action) {
            if (action == null) {
              throw new MissingRequiredPropertyException("GetAutoScalingConfigurationPolicyRule", "action");
            }
            this.action = action;
            return this;
        }
        @CustomType.Setter
        public Builder metrics(List<GetAutoScalingConfigurationPolicyRuleMetric> metrics) {
            if (metrics == null) {
              throw new MissingRequiredPropertyException("GetAutoScalingConfigurationPolicyRule", "metrics");
            }
            this.metrics = metrics;
            return this;
        }
        public Builder metrics(GetAutoScalingConfigurationPolicyRuleMetric... metrics) {
            return metrics(List.of(metrics));
        }
        public GetAutoScalingConfigurationPolicyRule build() {
            final var _resultValue = new GetAutoScalingConfigurationPolicyRule();
            _resultValue.action = action;
            _resultValue.metrics = metrics;
            return _resultValue;
        }
    }
}
