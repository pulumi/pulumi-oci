// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ContainerInstanceShapeConfig {
    /**
     * @return The total amount of memory available to the instance, in gigabytes.
     * 
     */
    private @Nullable Double memoryInGbs;
    /**
     * @return The networking bandwidth available to the instance, in gigabits per second.
     * 
     */
    private @Nullable Double networkingBandwidthInGbps;
    /**
     * @return The total number of OCPUs available to the instance.
     * 
     */
    private Double ocpus;
    /**
     * @return A short description of the instance&#39;s processor (CPU).
     * 
     */
    private @Nullable String processorDescription;

    private ContainerInstanceShapeConfig() {}
    /**
     * @return The total amount of memory available to the instance, in gigabytes.
     * 
     */
    public Optional<Double> memoryInGbs() {
        return Optional.ofNullable(this.memoryInGbs);
    }
    /**
     * @return The networking bandwidth available to the instance, in gigabits per second.
     * 
     */
    public Optional<Double> networkingBandwidthInGbps() {
        return Optional.ofNullable(this.networkingBandwidthInGbps);
    }
    /**
     * @return The total number of OCPUs available to the instance.
     * 
     */
    public Double ocpus() {
        return this.ocpus;
    }
    /**
     * @return A short description of the instance&#39;s processor (CPU).
     * 
     */
    public Optional<String> processorDescription() {
        return Optional.ofNullable(this.processorDescription);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ContainerInstanceShapeConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Double memoryInGbs;
        private @Nullable Double networkingBandwidthInGbps;
        private Double ocpus;
        private @Nullable String processorDescription;
        public Builder() {}
        public Builder(ContainerInstanceShapeConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.memoryInGbs = defaults.memoryInGbs;
    	      this.networkingBandwidthInGbps = defaults.networkingBandwidthInGbps;
    	      this.ocpus = defaults.ocpus;
    	      this.processorDescription = defaults.processorDescription;
        }

        @CustomType.Setter
        public Builder memoryInGbs(@Nullable Double memoryInGbs) {
            this.memoryInGbs = memoryInGbs;
            return this;
        }
        @CustomType.Setter
        public Builder networkingBandwidthInGbps(@Nullable Double networkingBandwidthInGbps) {
            this.networkingBandwidthInGbps = networkingBandwidthInGbps;
            return this;
        }
        @CustomType.Setter
        public Builder ocpus(Double ocpus) {
            this.ocpus = Objects.requireNonNull(ocpus);
            return this;
        }
        @CustomType.Setter
        public Builder processorDescription(@Nullable String processorDescription) {
            this.processorDescription = processorDescription;
            return this;
        }
        public ContainerInstanceShapeConfig build() {
            final var o = new ContainerInstanceShapeConfig();
            o.memoryInGbs = memoryInGbs;
            o.networkingBandwidthInGbps = networkingBandwidthInGbps;
            o.ocpus = ocpus;
            o.processorDescription = processorDescription;
            return o;
        }
    }
}