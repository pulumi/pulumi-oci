// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Autoscaling.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class AutoScalingConfigurationPolicyCapacity {
    /**
     * @return For a threshold-based autoscaling policy, this value is the initial number of instances to launch in the instance pool immediately after autoscaling is enabled. After autoscaling retrieves performance metrics, the number of instances is automatically adjusted from this initial number to a number that is based on the limits that you set.
     * 
     */
    private @Nullable Integer initial;
    /**
     * @return For a threshold-based autoscaling policy, this value is the maximum number of instances the instance pool is allowed to increase to (scale out).
     * 
     */
    private @Nullable Integer max;
    /**
     * @return For a threshold-based autoscaling policy, this value is the minimum number of instances the instance pool is allowed to decrease to (scale in).
     * 
     */
    private @Nullable Integer min;

    private AutoScalingConfigurationPolicyCapacity() {}
    /**
     * @return For a threshold-based autoscaling policy, this value is the initial number of instances to launch in the instance pool immediately after autoscaling is enabled. After autoscaling retrieves performance metrics, the number of instances is automatically adjusted from this initial number to a number that is based on the limits that you set.
     * 
     */
    public Optional<Integer> initial() {
        return Optional.ofNullable(this.initial);
    }
    /**
     * @return For a threshold-based autoscaling policy, this value is the maximum number of instances the instance pool is allowed to increase to (scale out).
     * 
     */
    public Optional<Integer> max() {
        return Optional.ofNullable(this.max);
    }
    /**
     * @return For a threshold-based autoscaling policy, this value is the minimum number of instances the instance pool is allowed to decrease to (scale in).
     * 
     */
    public Optional<Integer> min() {
        return Optional.ofNullable(this.min);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AutoScalingConfigurationPolicyCapacity defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Integer initial;
        private @Nullable Integer max;
        private @Nullable Integer min;
        public Builder() {}
        public Builder(AutoScalingConfigurationPolicyCapacity defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.initial = defaults.initial;
    	      this.max = defaults.max;
    	      this.min = defaults.min;
        }

        @CustomType.Setter
        public Builder initial(@Nullable Integer initial) {
            this.initial = initial;
            return this;
        }
        @CustomType.Setter
        public Builder max(@Nullable Integer max) {
            this.max = max;
            return this;
        }
        @CustomType.Setter
        public Builder min(@Nullable Integer min) {
            this.min = min;
            return this;
        }
        public AutoScalingConfigurationPolicyCapacity build() {
            final var o = new AutoScalingConfigurationPolicyCapacity();
            o.initial = initial;
            o.max = max;
            o.min = min;
            return o;
        }
    }
}