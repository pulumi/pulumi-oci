// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Double;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class InstanceConfigurationInstanceDetailsLaunchDetailsShapeConfig {
    /**
     * @return The baseline OCPU utilization for a subcore burstable VM instance. Leave this attribute blank for a non-burstable instance, or explicitly specify non-burstable with `BASELINE_1_1`.
     * 
     * The following values are supported:
     * * `BASELINE_1_8` - baseline usage is 1/8 of an OCPU.
     * * `BASELINE_1_2` - baseline usage is 1/2 of an OCPU.
     * * `BASELINE_1_1` - baseline usage is an entire OCPU. This represents a non-burstable instance.
     * 
     */
    private @Nullable String baselineOcpuUtilization;
    /**
     * @return The total amount of memory available to the instance, in gigabytes.
     * 
     */
    private @Nullable Double memoryInGbs;
    /**
     * @return The number of NVMe drives to be used for storage. A single drive has 6.8 TB available.
     * 
     */
    private @Nullable Integer nvmes;
    /**
     * @return The total number of OCPUs available to the instance.
     * 
     */
    private @Nullable Double ocpus;
    /**
     * @return The total number of VCPUs available to the instance. This can be used instead of OCPUs, in which case the actual number of OCPUs will be calculated based on this value and the actual hardware. This must be a multiple of 2.
     * 
     */
    private @Nullable Integer vcpus;

    private InstanceConfigurationInstanceDetailsLaunchDetailsShapeConfig() {}
    /**
     * @return The baseline OCPU utilization for a subcore burstable VM instance. Leave this attribute blank for a non-burstable instance, or explicitly specify non-burstable with `BASELINE_1_1`.
     * 
     * The following values are supported:
     * * `BASELINE_1_8` - baseline usage is 1/8 of an OCPU.
     * * `BASELINE_1_2` - baseline usage is 1/2 of an OCPU.
     * * `BASELINE_1_1` - baseline usage is an entire OCPU. This represents a non-burstable instance.
     * 
     */
    public Optional<String> baselineOcpuUtilization() {
        return Optional.ofNullable(this.baselineOcpuUtilization);
    }
    /**
     * @return The total amount of memory available to the instance, in gigabytes.
     * 
     */
    public Optional<Double> memoryInGbs() {
        return Optional.ofNullable(this.memoryInGbs);
    }
    /**
     * @return The number of NVMe drives to be used for storage. A single drive has 6.8 TB available.
     * 
     */
    public Optional<Integer> nvmes() {
        return Optional.ofNullable(this.nvmes);
    }
    /**
     * @return The total number of OCPUs available to the instance.
     * 
     */
    public Optional<Double> ocpus() {
        return Optional.ofNullable(this.ocpus);
    }
    /**
     * @return The total number of VCPUs available to the instance. This can be used instead of OCPUs, in which case the actual number of OCPUs will be calculated based on this value and the actual hardware. This must be a multiple of 2.
     * 
     */
    public Optional<Integer> vcpus() {
        return Optional.ofNullable(this.vcpus);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(InstanceConfigurationInstanceDetailsLaunchDetailsShapeConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String baselineOcpuUtilization;
        private @Nullable Double memoryInGbs;
        private @Nullable Integer nvmes;
        private @Nullable Double ocpus;
        private @Nullable Integer vcpus;
        public Builder() {}
        public Builder(InstanceConfigurationInstanceDetailsLaunchDetailsShapeConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.baselineOcpuUtilization = defaults.baselineOcpuUtilization;
    	      this.memoryInGbs = defaults.memoryInGbs;
    	      this.nvmes = defaults.nvmes;
    	      this.ocpus = defaults.ocpus;
    	      this.vcpus = defaults.vcpus;
        }

        @CustomType.Setter
        public Builder baselineOcpuUtilization(@Nullable String baselineOcpuUtilization) {

            this.baselineOcpuUtilization = baselineOcpuUtilization;
            return this;
        }
        @CustomType.Setter
        public Builder memoryInGbs(@Nullable Double memoryInGbs) {

            this.memoryInGbs = memoryInGbs;
            return this;
        }
        @CustomType.Setter
        public Builder nvmes(@Nullable Integer nvmes) {

            this.nvmes = nvmes;
            return this;
        }
        @CustomType.Setter
        public Builder ocpus(@Nullable Double ocpus) {

            this.ocpus = ocpus;
            return this;
        }
        @CustomType.Setter
        public Builder vcpus(@Nullable Integer vcpus) {

            this.vcpus = vcpus;
            return this;
        }
        public InstanceConfigurationInstanceDetailsLaunchDetailsShapeConfig build() {
            final var _resultValue = new InstanceConfigurationInstanceDetailsLaunchDetailsShapeConfig();
            _resultValue.baselineOcpuUtilization = baselineOcpuUtilization;
            _resultValue.memoryInGbs = memoryInGbs;
            _resultValue.nvmes = nvmes;
            _resultValue.ocpus = ocpus;
            _resultValue.vcpus = vcpus;
            return _resultValue;
        }
    }
}
