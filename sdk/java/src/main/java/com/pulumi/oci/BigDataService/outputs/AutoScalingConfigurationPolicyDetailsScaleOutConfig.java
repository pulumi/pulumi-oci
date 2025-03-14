// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.BigDataService.outputs.AutoScalingConfigurationPolicyDetailsScaleOutConfigMetric;
import java.lang.Integer;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class AutoScalingConfigurationPolicyDetailsScaleOutConfig {
    /**
     * @return (Updatable) This value is the maximum number of nodes the cluster can be scaled-out to.
     * 
     */
    private @Nullable Integer maxNodeCount;
    /**
     * @return (Updatable) Metric and threshold details for triggering an autoscale action.
     * 
     */
    private @Nullable AutoScalingConfigurationPolicyDetailsScaleOutConfigMetric metric;
    /**
     * @return (Updatable) This value is the number of nodes to add during a scale-out event.
     * 
     */
    private @Nullable Integer stepSize;

    private AutoScalingConfigurationPolicyDetailsScaleOutConfig() {}
    /**
     * @return (Updatable) This value is the maximum number of nodes the cluster can be scaled-out to.
     * 
     */
    public Optional<Integer> maxNodeCount() {
        return Optional.ofNullable(this.maxNodeCount);
    }
    /**
     * @return (Updatable) Metric and threshold details for triggering an autoscale action.
     * 
     */
    public Optional<AutoScalingConfigurationPolicyDetailsScaleOutConfigMetric> metric() {
        return Optional.ofNullable(this.metric);
    }
    /**
     * @return (Updatable) This value is the number of nodes to add during a scale-out event.
     * 
     */
    public Optional<Integer> stepSize() {
        return Optional.ofNullable(this.stepSize);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AutoScalingConfigurationPolicyDetailsScaleOutConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Integer maxNodeCount;
        private @Nullable AutoScalingConfigurationPolicyDetailsScaleOutConfigMetric metric;
        private @Nullable Integer stepSize;
        public Builder() {}
        public Builder(AutoScalingConfigurationPolicyDetailsScaleOutConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.maxNodeCount = defaults.maxNodeCount;
    	      this.metric = defaults.metric;
    	      this.stepSize = defaults.stepSize;
        }

        @CustomType.Setter
        public Builder maxNodeCount(@Nullable Integer maxNodeCount) {

            this.maxNodeCount = maxNodeCount;
            return this;
        }
        @CustomType.Setter
        public Builder metric(@Nullable AutoScalingConfigurationPolicyDetailsScaleOutConfigMetric metric) {

            this.metric = metric;
            return this;
        }
        @CustomType.Setter
        public Builder stepSize(@Nullable Integer stepSize) {

            this.stepSize = stepSize;
            return this;
        }
        public AutoScalingConfigurationPolicyDetailsScaleOutConfig build() {
            final var _resultValue = new AutoScalingConfigurationPolicyDetailsScaleOutConfig();
            _resultValue.maxNodeCount = maxNodeCount;
            _resultValue.metric = metric;
            _resultValue.stepSize = stepSize;
            return _resultValue;
        }
    }
}
