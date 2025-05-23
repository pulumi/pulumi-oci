// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetOperationsInsightsWarehouseResourceUsageSummaryResult {
    /**
     * @return Number of OCPUs used by OPSI Warehouse ADW. Can be fractional.
     * 
     */
    private Double cpuUsed;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String operationsInsightsWarehouseId;
    /**
     * @return Possible lifecycle states
     * 
     */
    private String state;
    /**
     * @return Storage by OPSI Warehouse ADW in GB.
     * 
     */
    private Double storageUsedInGbs;

    private GetOperationsInsightsWarehouseResourceUsageSummaryResult() {}
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
    @CustomType.Builder
    public static final class Builder {
        private Double cpuUsed;
        private String id;
        private String operationsInsightsWarehouseId;
        private String state;
        private Double storageUsedInGbs;
        public Builder() {}
        public Builder(GetOperationsInsightsWarehouseResourceUsageSummaryResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.cpuUsed = defaults.cpuUsed;
    	      this.id = defaults.id;
    	      this.operationsInsightsWarehouseId = defaults.operationsInsightsWarehouseId;
    	      this.state = defaults.state;
    	      this.storageUsedInGbs = defaults.storageUsedInGbs;
        }

        @CustomType.Setter
        public Builder cpuUsed(Double cpuUsed) {
            if (cpuUsed == null) {
              throw new MissingRequiredPropertyException("GetOperationsInsightsWarehouseResourceUsageSummaryResult", "cpuUsed");
            }
            this.cpuUsed = cpuUsed;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetOperationsInsightsWarehouseResourceUsageSummaryResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder operationsInsightsWarehouseId(String operationsInsightsWarehouseId) {
            if (operationsInsightsWarehouseId == null) {
              throw new MissingRequiredPropertyException("GetOperationsInsightsWarehouseResourceUsageSummaryResult", "operationsInsightsWarehouseId");
            }
            this.operationsInsightsWarehouseId = operationsInsightsWarehouseId;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetOperationsInsightsWarehouseResourceUsageSummaryResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder storageUsedInGbs(Double storageUsedInGbs) {
            if (storageUsedInGbs == null) {
              throw new MissingRequiredPropertyException("GetOperationsInsightsWarehouseResourceUsageSummaryResult", "storageUsedInGbs");
            }
            this.storageUsedInGbs = storageUsedInGbs;
            return this;
        }
        public GetOperationsInsightsWarehouseResourceUsageSummaryResult build() {
            final var _resultValue = new GetOperationsInsightsWarehouseResourceUsageSummaryResult();
            _resultValue.cpuUsed = cpuUsed;
            _resultValue.id = id;
            _resultValue.operationsInsightsWarehouseId = operationsInsightsWarehouseId;
            _resultValue.state = state;
            _resultValue.storageUsedInGbs = storageUsedInGbs;
            return _resultValue;
        }
    }
}
