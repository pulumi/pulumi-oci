// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Autoscaling.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAutoScalingConfigurationPolicyExecutionSchedule {
    /**
     * @return A cron expression that represents the time at which to execute the autoscaling policy.
     * 
     */
    private String expression;
    /**
     * @return The time zone for the execution schedule.
     * 
     */
    private String timezone;
    /**
     * @return The type of action to take.
     * 
     */
    private String type;

    private GetAutoScalingConfigurationPolicyExecutionSchedule() {}
    /**
     * @return A cron expression that represents the time at which to execute the autoscaling policy.
     * 
     */
    public String expression() {
        return this.expression;
    }
    /**
     * @return The time zone for the execution schedule.
     * 
     */
    public String timezone() {
        return this.timezone;
    }
    /**
     * @return The type of action to take.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutoScalingConfigurationPolicyExecutionSchedule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String expression;
        private String timezone;
        private String type;
        public Builder() {}
        public Builder(GetAutoScalingConfigurationPolicyExecutionSchedule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.expression = defaults.expression;
    	      this.timezone = defaults.timezone;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder expression(String expression) {
            if (expression == null) {
              throw new MissingRequiredPropertyException("GetAutoScalingConfigurationPolicyExecutionSchedule", "expression");
            }
            this.expression = expression;
            return this;
        }
        @CustomType.Setter
        public Builder timezone(String timezone) {
            if (timezone == null) {
              throw new MissingRequiredPropertyException("GetAutoScalingConfigurationPolicyExecutionSchedule", "timezone");
            }
            this.timezone = timezone;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetAutoScalingConfigurationPolicyExecutionSchedule", "type");
            }
            this.type = type;
            return this;
        }
        public GetAutoScalingConfigurationPolicyExecutionSchedule build() {
            final var _resultValue = new GetAutoScalingConfigurationPolicyExecutionSchedule();
            _resultValue.expression = expression;
            _resultValue.timezone = timezone;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
