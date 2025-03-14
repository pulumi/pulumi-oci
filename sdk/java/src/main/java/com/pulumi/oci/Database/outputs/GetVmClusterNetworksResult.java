// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.outputs.GetVmClusterNetworksFilter;
import com.pulumi.oci.Database.outputs.GetVmClusterNetworksVmClusterNetwork;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetVmClusterNetworksResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The user-friendly name for the VM cluster network. The name does not need to be unique.
     * 
     */
    private @Nullable String displayName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     * 
     */
    private String exadataInfrastructureId;
    private @Nullable List<GetVmClusterNetworksFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The current state of the VM cluster network nodes. CREATING - The resource is being created REQUIRES_VALIDATION - The resource is created and may not be usable until it is validated. VALIDATING - The resource is being validated and not available to use. VALIDATED - The resource is validated and is available for consumption by VM cluster. VALIDATION_FAILED - The resource validation has failed and might require user input to be corrected. UPDATING - The resource is being updated and not available to use. ALLOCATED - The resource is currently being used by VM cluster. TERMINATING - The resource is being deleted and not available to use. TERMINATED - The resource is deleted and unavailable. FAILED - The resource is in a failed state due to validation or other errors.
     * 
     */
    private @Nullable String state;
    /**
     * @return The list of vm_cluster_networks.
     * 
     */
    private List<GetVmClusterNetworksVmClusterNetwork> vmClusterNetworks;

    private GetVmClusterNetworksResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The user-friendly name for the VM cluster network. The name does not need to be unique.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     * 
     */
    public String exadataInfrastructureId() {
        return this.exadataInfrastructureId;
    }
    public List<GetVmClusterNetworksFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The current state of the VM cluster network nodes. CREATING - The resource is being created REQUIRES_VALIDATION - The resource is created and may not be usable until it is validated. VALIDATING - The resource is being validated and not available to use. VALIDATED - The resource is validated and is available for consumption by VM cluster. VALIDATION_FAILED - The resource validation has failed and might require user input to be corrected. UPDATING - The resource is being updated and not available to use. ALLOCATED - The resource is currently being used by VM cluster. TERMINATING - The resource is being deleted and not available to use. TERMINATED - The resource is deleted and unavailable. FAILED - The resource is in a failed state due to validation or other errors.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The list of vm_cluster_networks.
     * 
     */
    public List<GetVmClusterNetworksVmClusterNetwork> vmClusterNetworks() {
        return this.vmClusterNetworks;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVmClusterNetworksResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private String exadataInfrastructureId;
        private @Nullable List<GetVmClusterNetworksFilter> filters;
        private String id;
        private @Nullable String state;
        private List<GetVmClusterNetworksVmClusterNetwork> vmClusterNetworks;
        public Builder() {}
        public Builder(GetVmClusterNetworksResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.exadataInfrastructureId = defaults.exadataInfrastructureId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
    	      this.vmClusterNetworks = defaults.vmClusterNetworks;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetVmClusterNetworksResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder exadataInfrastructureId(String exadataInfrastructureId) {
            if (exadataInfrastructureId == null) {
              throw new MissingRequiredPropertyException("GetVmClusterNetworksResult", "exadataInfrastructureId");
            }
            this.exadataInfrastructureId = exadataInfrastructureId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetVmClusterNetworksFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetVmClusterNetworksFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetVmClusterNetworksResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder vmClusterNetworks(List<GetVmClusterNetworksVmClusterNetwork> vmClusterNetworks) {
            if (vmClusterNetworks == null) {
              throw new MissingRequiredPropertyException("GetVmClusterNetworksResult", "vmClusterNetworks");
            }
            this.vmClusterNetworks = vmClusterNetworks;
            return this;
        }
        public Builder vmClusterNetworks(GetVmClusterNetworksVmClusterNetwork... vmClusterNetworks) {
            return vmClusterNetworks(List.of(vmClusterNetworks));
        }
        public GetVmClusterNetworksResult build() {
            final var _resultValue = new GetVmClusterNetworksResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.displayName = displayName;
            _resultValue.exadataInfrastructureId = exadataInfrastructureId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.state = state;
            _resultValue.vmClusterNetworks = vmClusterNetworks;
            return _resultValue;
        }
    }
}
