// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Autoscaling.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRuleMetricThreshold {
    /**
     * @return The comparison operator to use. Options are greater than (`GT`), greater than or equal to (`GTE`), less than (`LT`), and less than or equal to (`LTE`).
     * 
     */
    private String operator;
    private Integer value;

    private GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRuleMetricThreshold() {}
    /**
     * @return The comparison operator to use. Options are greater than (`GT`), greater than or equal to (`GTE`), less than (`LT`), and less than or equal to (`LTE`).
     * 
     */
    public String operator() {
        return this.operator;
    }
    public Integer value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRuleMetricThreshold defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String operator;
        private Integer value;
        public Builder() {}
        public Builder(GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRuleMetricThreshold defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.operator = defaults.operator;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder operator(String operator) {
            if (operator == null) {
              throw new MissingRequiredPropertyException("GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRuleMetricThreshold", "operator");
            }
            this.operator = operator;
            return this;
        }
        @CustomType.Setter
        public Builder value(Integer value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRuleMetricThreshold", "value");
            }
            this.value = value;
            return this;
        }
        public GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRuleMetricThreshold build() {
            final var _resultValue = new GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRuleMetricThreshold();
            _resultValue.operator = operator;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
