// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class BdsInstanceEdgeNodeShapeConfig {
    /**
     * @return The total amount of memory available to the node, in gigabytes
     * 
     */
    private @Nullable Integer memoryInGbs;
    /**
     * @return The number of NVMe drives to be used for storage. A single drive has 6.8 TB available.
     * 
     */
    private @Nullable Integer nvmes;
    /**
     * @return The total number of OCPUs available to the node.
     * 
     */
    private @Nullable Integer ocpus;

    private BdsInstanceEdgeNodeShapeConfig() {}
    /**
     * @return The total amount of memory available to the node, in gigabytes
     * 
     */
    public Optional<Integer> memoryInGbs() {
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
     * @return The total number of OCPUs available to the node.
     * 
     */
    public Optional<Integer> ocpus() {
        return Optional.ofNullable(this.ocpus);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(BdsInstanceEdgeNodeShapeConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Integer memoryInGbs;
        private @Nullable Integer nvmes;
        private @Nullable Integer ocpus;
        public Builder() {}
        public Builder(BdsInstanceEdgeNodeShapeConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.memoryInGbs = defaults.memoryInGbs;
    	      this.nvmes = defaults.nvmes;
    	      this.ocpus = defaults.ocpus;
        }

        @CustomType.Setter
        public Builder memoryInGbs(@Nullable Integer memoryInGbs) {
            this.memoryInGbs = memoryInGbs;
            return this;
        }
        @CustomType.Setter
        public Builder nvmes(@Nullable Integer nvmes) {
            this.nvmes = nvmes;
            return this;
        }
        @CustomType.Setter
        public Builder ocpus(@Nullable Integer ocpus) {
            this.ocpus = ocpus;
            return this;
        }
        public BdsInstanceEdgeNodeShapeConfig build() {
            final var o = new BdsInstanceEdgeNodeShapeConfig();
            o.memoryInGbs = memoryInGbs;
            o.nvmes = nvmes;
            o.ocpus = ocpus;
            return o;
        }
    }
}