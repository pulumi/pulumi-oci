// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.BigDataService.outputs.GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleUpConfigMetric;
import java.lang.Integer;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleUpConfig {
    private Integer maxMemoryPerNode;
    private Integer maxOcpusPerNode;
    private Integer memoryStepSize;
    private List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleUpConfigMetric> metrics;
    private Integer ocpuStepSize;

    private GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleUpConfig() {}
    public Integer maxMemoryPerNode() {
        return this.maxMemoryPerNode;
    }
    public Integer maxOcpusPerNode() {
        return this.maxOcpusPerNode;
    }
    public Integer memoryStepSize() {
        return this.memoryStepSize;
    }
    public List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleUpConfigMetric> metrics() {
        return this.metrics;
    }
    public Integer ocpuStepSize() {
        return this.ocpuStepSize;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleUpConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer maxMemoryPerNode;
        private Integer maxOcpusPerNode;
        private Integer memoryStepSize;
        private List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleUpConfigMetric> metrics;
        private Integer ocpuStepSize;
        public Builder() {}
        public Builder(GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleUpConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.maxMemoryPerNode = defaults.maxMemoryPerNode;
    	      this.maxOcpusPerNode = defaults.maxOcpusPerNode;
    	      this.memoryStepSize = defaults.memoryStepSize;
    	      this.metrics = defaults.metrics;
    	      this.ocpuStepSize = defaults.ocpuStepSize;
        }

        @CustomType.Setter
        public Builder maxMemoryPerNode(Integer maxMemoryPerNode) {
            this.maxMemoryPerNode = Objects.requireNonNull(maxMemoryPerNode);
            return this;
        }
        @CustomType.Setter
        public Builder maxOcpusPerNode(Integer maxOcpusPerNode) {
            this.maxOcpusPerNode = Objects.requireNonNull(maxOcpusPerNode);
            return this;
        }
        @CustomType.Setter
        public Builder memoryStepSize(Integer memoryStepSize) {
            this.memoryStepSize = Objects.requireNonNull(memoryStepSize);
            return this;
        }
        @CustomType.Setter
        public Builder metrics(List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleUpConfigMetric> metrics) {
            this.metrics = Objects.requireNonNull(metrics);
            return this;
        }
        public Builder metrics(GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleUpConfigMetric... metrics) {
            return metrics(List.of(metrics));
        }
        @CustomType.Setter
        public Builder ocpuStepSize(Integer ocpuStepSize) {
            this.ocpuStepSize = Objects.requireNonNull(ocpuStepSize);
            return this;
        }
        public GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleUpConfig build() {
            final var o = new GetAutoScalingConfigurationsAutoScalingConfigurationPolicyDetailScaleUpConfig();
            o.maxMemoryPerNode = maxMemoryPerNode;
            o.maxOcpusPerNode = maxOcpusPerNode;
            o.memoryStepSize = memoryStepSize;
            o.metrics = metrics;
            o.ocpuStepSize = ocpuStepSize;
            return o;
        }
    }
}