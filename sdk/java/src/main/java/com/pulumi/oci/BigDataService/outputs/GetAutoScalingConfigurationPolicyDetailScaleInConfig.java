// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.BigDataService.outputs.GetAutoScalingConfigurationPolicyDetailScaleInConfigMetric;
import java.lang.Integer;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAutoScalingConfigurationPolicyDetailScaleInConfig {
    /**
     * @return Metric and threshold details for triggering an autoscale action.
     * 
     */
    private List<GetAutoScalingConfigurationPolicyDetailScaleInConfigMetric> metrics;
    /**
     * @return This value is the minimum number of nodes the cluster can be scaled-in to.
     * 
     */
    private Integer minNodeCount;
    /**
     * @return This value is the number of nodes to add during a scale-out event.
     * 
     */
    private Integer stepSize;

    private GetAutoScalingConfigurationPolicyDetailScaleInConfig() {}
    /**
     * @return Metric and threshold details for triggering an autoscale action.
     * 
     */
    public List<GetAutoScalingConfigurationPolicyDetailScaleInConfigMetric> metrics() {
        return this.metrics;
    }
    /**
     * @return This value is the minimum number of nodes the cluster can be scaled-in to.
     * 
     */
    public Integer minNodeCount() {
        return this.minNodeCount;
    }
    /**
     * @return This value is the number of nodes to add during a scale-out event.
     * 
     */
    public Integer stepSize() {
        return this.stepSize;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutoScalingConfigurationPolicyDetailScaleInConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetAutoScalingConfigurationPolicyDetailScaleInConfigMetric> metrics;
        private Integer minNodeCount;
        private Integer stepSize;
        public Builder() {}
        public Builder(GetAutoScalingConfigurationPolicyDetailScaleInConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.metrics = defaults.metrics;
    	      this.minNodeCount = defaults.minNodeCount;
    	      this.stepSize = defaults.stepSize;
        }

        @CustomType.Setter
        public Builder metrics(List<GetAutoScalingConfigurationPolicyDetailScaleInConfigMetric> metrics) {
            this.metrics = Objects.requireNonNull(metrics);
            return this;
        }
        public Builder metrics(GetAutoScalingConfigurationPolicyDetailScaleInConfigMetric... metrics) {
            return metrics(List.of(metrics));
        }
        @CustomType.Setter
        public Builder minNodeCount(Integer minNodeCount) {
            this.minNodeCount = Objects.requireNonNull(minNodeCount);
            return this;
        }
        @CustomType.Setter
        public Builder stepSize(Integer stepSize) {
            this.stepSize = Objects.requireNonNull(stepSize);
            return this;
        }
        public GetAutoScalingConfigurationPolicyDetailScaleInConfig build() {
            final var o = new GetAutoScalingConfigurationPolicyDetailScaleInConfig();
            o.metrics = metrics;
            o.minNodeCount = minNodeCount;
            o.stepSize = stepSize;
            return o;
        }
    }
}