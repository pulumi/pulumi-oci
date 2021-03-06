// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetOperationsInsightsWarehouseResourceUsageSummaryResult {
    /**
     * @return Number of OCPUs used by OPSI Warehouse ADW. Can be fractional.
     * 
     */
    private final Double cpuUsed;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    private final String operationsInsightsWarehouseId;
    /**
     * @return Possible lifecycle states
     * 
     */
    private final String state;
    /**
     * @return Storage by OPSI Warehouse ADW in GB.
     * 
     */
    private final Double storageUsedInGbs;

    @CustomType.Constructor
    private GetOperationsInsightsWarehouseResourceUsageSummaryResult(
        @CustomType.Parameter("cpuUsed") Double cpuUsed,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("operationsInsightsWarehouseId") String operationsInsightsWarehouseId,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("storageUsedInGbs") Double storageUsedInGbs) {
        this.cpuUsed = cpuUsed;
        this.id = id;
        this.operationsInsightsWarehouseId = operationsInsightsWarehouseId;
        this.state = state;
        this.storageUsedInGbs = storageUsedInGbs;
    }

    /**
     * @return Number of OCPUs used by OPSI Warehouse ADW. Can be fractional.
     * 
     */
    public Double cpuUsed() {
        return this.cpuUsed;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String operationsInsightsWarehouseId() {
        return this.operationsInsightsWarehouseId;
    }
    /**
     * @return Possible lifecycle states
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Storage by OPSI Warehouse ADW in GB.
     * 
     */
    public Double storageUsedInGbs() {
        return this.storageUsedInGbs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetOperationsInsightsWarehouseResourceUsageSummaryResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Double cpuUsed;
        private String id;
        private String operationsInsightsWarehouseId;
        private String state;
        private Double storageUsedInGbs;

        public Builder() {
    	      // Empty
        }

        public Builder(GetOperationsInsightsWarehouseResourceUsageSummaryResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.cpuUsed = defaults.cpuUsed;
    	      this.id = defaults.id;
    	      this.operationsInsightsWarehouseId = defaults.operationsInsightsWarehouseId;
    	      this.state = defaults.state;
    	      this.storageUsedInGbs = defaults.storageUsedInGbs;
        }

        public Builder cpuUsed(Double cpuUsed) {
            this.cpuUsed = Objects.requireNonNull(cpuUsed);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder operationsInsightsWarehouseId(String operationsInsightsWarehouseId) {
            this.operationsInsightsWarehouseId = Objects.requireNonNull(operationsInsightsWarehouseId);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder storageUsedInGbs(Double storageUsedInGbs) {
            this.storageUsedInGbs = Objects.requireNonNull(storageUsedInGbs);
            return this;
        }        public GetOperationsInsightsWarehouseResourceUsageSummaryResult build() {
            return new GetOperationsInsightsWarehouseResourceUsageSummaryResult(cpuUsed, id, operationsInsightsWarehouseId, state, storageUsedInGbs);
        }
    }
}
