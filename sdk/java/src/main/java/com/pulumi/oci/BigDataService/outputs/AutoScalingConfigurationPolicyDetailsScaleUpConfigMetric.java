// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.BigDataService.outputs.AutoScalingConfigurationPolicyDetailsScaleUpConfigMetricThreshold;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class AutoScalingConfigurationPolicyDetailsScaleUpConfigMetric {
    /**
     * @return (Updatable) Allowed value is CPU_UTILIZATION.
     * 
     */
    private @Nullable String metricType;
    /**
     * @return (Updatable) An autoscale action is triggered when a performance metric exceeds a threshold.
     * 
     */
    private @Nullable AutoScalingConfigurationPolicyDetailsScaleUpConfigMetricThreshold threshold;

    private AutoScalingConfigurationPolicyDetailsScaleUpConfigMetric() {}
    /**
     * @return (Updatable) Allowed value is CPU_UTILIZATION.
     * 
     */
    public Optional<String> metricType() {
        return Optional.ofNullable(this.metricType);
    }
    /**
     * @return (Updatable) An autoscale action is triggered when a performance metric exceeds a threshold.
     * 
     */
    public Optional<AutoScalingConfigurationPolicyDetailsScaleUpConfigMetricThreshold> threshold() {
        return Optional.ofNullable(this.threshold);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AutoScalingConfigurationPolicyDetailsScaleUpConfigMetric defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String metricType;
        private @Nullable AutoScalingConfigurationPolicyDetailsScaleUpConfigMetricThreshold threshold;
        public Builder() {}
        public Builder(AutoScalingConfigurationPolicyDetailsScaleUpConfigMetric defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.metricType = defaults.metricType;
    	      this.threshold = defaults.threshold;
        }

        @CustomType.Setter
        public Builder metricType(@Nullable String metricType) {
            this.metricType = metricType;
            return this;
        }
        @CustomType.Setter
        public Builder threshold(@Nullable AutoScalingConfigurationPolicyDetailsScaleUpConfigMetricThreshold threshold) {
            this.threshold = threshold;
            return this;
        }
        public AutoScalingConfigurationPolicyDetailsScaleUpConfigMetric build() {
            final var o = new AutoScalingConfigurationPolicyDetailsScaleUpConfigMetric();
            o.metricType = metricType;
            o.threshold = threshold;
            return o;
        }
    }
}