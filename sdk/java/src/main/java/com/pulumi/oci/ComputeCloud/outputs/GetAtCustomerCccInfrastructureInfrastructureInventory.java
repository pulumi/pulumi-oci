// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ComputeCloud.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAtCustomerCccInfrastructureInfrastructureInventory {
    /**
     * @return The number of storage trays in the Compute Cloud@Customer infrastructure rack that are designated for capacity storage.
     * 
     */
    private Integer capacityStorageTrayCount;
    /**
     * @return The number of compute nodes that are available and usable on the Compute Cloud@Customer infrastructure rack. There is no distinction of compute node type in this information.
     * 
     */
    private Integer computeNodeCount;
    /**
     * @return The number of management nodes that are available and in active use on the Compute Cloud@Customer infrastructure rack.
     * 
     */
    private Integer managementNodeCount;
    /**
     * @return The number of storage trays in the Compute Cloud@Customer infrastructure rack that are designated for performance storage.
     * 
     */
    private Integer performanceStorageTrayCount;
    /**
     * @return The serial number of the Compute Cloud@Customer infrastructure rack.
     * 
     */
    private String serialNumber;

    private GetAtCustomerCccInfrastructureInfrastructureInventory() {}
    /**
     * @return The number of storage trays in the Compute Cloud@Customer infrastructure rack that are designated for capacity storage.
     * 
     */
    public Integer capacityStorageTrayCount() {
        return this.capacityStorageTrayCount;
    }
    /**
     * @return The number of compute nodes that are available and usable on the Compute Cloud@Customer infrastructure rack. There is no distinction of compute node type in this information.
     * 
     */
    public Integer computeNodeCount() {
        return this.computeNodeCount;
    }
    /**
     * @return The number of management nodes that are available and in active use on the Compute Cloud@Customer infrastructure rack.
     * 
     */
    public Integer managementNodeCount() {
        return this.managementNodeCount;
    }
    /**
     * @return The number of storage trays in the Compute Cloud@Customer infrastructure rack that are designated for performance storage.
     * 
     */
    public Integer performanceStorageTrayCount() {
        return this.performanceStorageTrayCount;
    }
    /**
     * @return The serial number of the Compute Cloud@Customer infrastructure rack.
     * 
     */
    public String serialNumber() {
        return this.serialNumber;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAtCustomerCccInfrastructureInfrastructureInventory defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer capacityStorageTrayCount;
        private Integer computeNodeCount;
        private Integer managementNodeCount;
        private Integer performanceStorageTrayCount;
        private String serialNumber;
        public Builder() {}
        public Builder(GetAtCustomerCccInfrastructureInfrastructureInventory defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.capacityStorageTrayCount = defaults.capacityStorageTrayCount;
    	      this.computeNodeCount = defaults.computeNodeCount;
    	      this.managementNodeCount = defaults.managementNodeCount;
    	      this.performanceStorageTrayCount = defaults.performanceStorageTrayCount;
    	      this.serialNumber = defaults.serialNumber;
        }

        @CustomType.Setter
        public Builder capacityStorageTrayCount(Integer capacityStorageTrayCount) {
            this.capacityStorageTrayCount = Objects.requireNonNull(capacityStorageTrayCount);
            return this;
        }
        @CustomType.Setter
        public Builder computeNodeCount(Integer computeNodeCount) {
            this.computeNodeCount = Objects.requireNonNull(computeNodeCount);
            return this;
        }
        @CustomType.Setter
        public Builder managementNodeCount(Integer managementNodeCount) {
            this.managementNodeCount = Objects.requireNonNull(managementNodeCount);
            return this;
        }
        @CustomType.Setter
        public Builder performanceStorageTrayCount(Integer performanceStorageTrayCount) {
            this.performanceStorageTrayCount = Objects.requireNonNull(performanceStorageTrayCount);
            return this;
        }
        @CustomType.Setter
        public Builder serialNumber(String serialNumber) {
            this.serialNumber = Objects.requireNonNull(serialNumber);
            return this;
        }
        public GetAtCustomerCccInfrastructureInfrastructureInventory build() {
            final var o = new GetAtCustomerCccInfrastructureInfrastructureInventory();
            o.capacityStorageTrayCount = capacityStorageTrayCount;
            o.computeNodeCount = computeNodeCount;
            o.managementNodeCount = managementNodeCount;
            o.performanceStorageTrayCount = performanceStorageTrayCount;
            o.serialNumber = serialNumber;
            return o;
        }
    }
}