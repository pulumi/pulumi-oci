// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetComputeCapacityReservationInstanceReservationConfigClusterConfig {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the HPC island.
     * 
     */
    private String hpcIslandId;
    /**
     * @return The list of OCIDs of the network blocks.
     * 
     */
    private List<String> networkBlockIds;

    private GetComputeCapacityReservationInstanceReservationConfigClusterConfig() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the HPC island.
     * 
     */
    public String hpcIslandId() {
        return this.hpcIslandId;
    }
    /**
     * @return The list of OCIDs of the network blocks.
     * 
     */
    public List<String> networkBlockIds() {
        return this.networkBlockIds;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetComputeCapacityReservationInstanceReservationConfigClusterConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String hpcIslandId;
        private List<String> networkBlockIds;
        public Builder() {}
        public Builder(GetComputeCapacityReservationInstanceReservationConfigClusterConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.hpcIslandId = defaults.hpcIslandId;
    	      this.networkBlockIds = defaults.networkBlockIds;
        }

        @CustomType.Setter
        public Builder hpcIslandId(String hpcIslandId) {
            if (hpcIslandId == null) {
              throw new MissingRequiredPropertyException("GetComputeCapacityReservationInstanceReservationConfigClusterConfig", "hpcIslandId");
            }
            this.hpcIslandId = hpcIslandId;
            return this;
        }
        @CustomType.Setter
        public Builder networkBlockIds(List<String> networkBlockIds) {
            if (networkBlockIds == null) {
              throw new MissingRequiredPropertyException("GetComputeCapacityReservationInstanceReservationConfigClusterConfig", "networkBlockIds");
            }
            this.networkBlockIds = networkBlockIds;
            return this;
        }
        public Builder networkBlockIds(String... networkBlockIds) {
            return networkBlockIds(List.of(networkBlockIds));
        }
        public GetComputeCapacityReservationInstanceReservationConfigClusterConfig build() {
            final var _resultValue = new GetComputeCapacityReservationInstanceReservationConfigClusterConfig();
            _resultValue.hpcIslandId = hpcIslandId;
            _resultValue.networkBlockIds = networkBlockIds;
            return _resultValue;
        }
    }
}
