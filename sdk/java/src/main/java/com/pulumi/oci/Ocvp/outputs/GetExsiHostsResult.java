// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Ocvp.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Ocvp.outputs.GetExsiHostsEsxiHostCollection;
import com.pulumi.oci.Ocvp.outputs.GetExsiHostsFilter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetExsiHostsResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Cluster that the ESXi host belongs to.
     * 
     */
    private @Nullable String clusterId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the Cluster.
     * 
     */
    private @Nullable String compartmentId;
    /**
     * @return In terms of implementation, an ESXi host is a Compute instance that is configured with the chosen bundle of VMware software. The `computeInstanceId` is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of that Compute instance.
     * 
     */
    private @Nullable String computeInstanceId;
    /**
     * @return A descriptive name for the ESXi host. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    /**
     * @return The list of esxi_host_collection.
     * 
     */
    private List<GetExsiHostsEsxiHostCollection> esxiHostCollections;
    private @Nullable List<GetExsiHostsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable Boolean isBillingDonorsOnly;
    private @Nullable Boolean isSwapBillingOnly;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC that the ESXi host belongs to.
     * 
     */
    private @Nullable String sddcId;
    /**
     * @return The current state of the ESXi host.
     * 
     */
    private @Nullable String state;

    private GetExsiHostsResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Cluster that the ESXi host belongs to.
     * 
     */
    public Optional<String> clusterId() {
        return Optional.ofNullable(this.clusterId);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the Cluster.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return In terms of implementation, an ESXi host is a Compute instance that is configured with the chosen bundle of VMware software. The `computeInstanceId` is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of that Compute instance.
     * 
     */
    public Optional<String> computeInstanceId() {
        return Optional.ofNullable(this.computeInstanceId);
    }
    /**
     * @return A descriptive name for the ESXi host. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return The list of esxi_host_collection.
     * 
     */
    public List<GetExsiHostsEsxiHostCollection> esxiHostCollections() {
        return this.esxiHostCollections;
    }
    public List<GetExsiHostsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<Boolean> isBillingDonorsOnly() {
        return Optional.ofNullable(this.isBillingDonorsOnly);
    }
    public Optional<Boolean> isSwapBillingOnly() {
        return Optional.ofNullable(this.isSwapBillingOnly);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the SDDC that the ESXi host belongs to.
     * 
     */
    public Optional<String> sddcId() {
        return Optional.ofNullable(this.sddcId);
    }
    /**
     * @return The current state of the ESXi host.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExsiHostsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String clusterId;
        private @Nullable String compartmentId;
        private @Nullable String computeInstanceId;
        private @Nullable String displayName;
        private List<GetExsiHostsEsxiHostCollection> esxiHostCollections;
        private @Nullable List<GetExsiHostsFilter> filters;
        private String id;
        private @Nullable Boolean isBillingDonorsOnly;
        private @Nullable Boolean isSwapBillingOnly;
        private @Nullable String sddcId;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetExsiHostsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.clusterId = defaults.clusterId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.computeInstanceId = defaults.computeInstanceId;
    	      this.displayName = defaults.displayName;
    	      this.esxiHostCollections = defaults.esxiHostCollections;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.isBillingDonorsOnly = defaults.isBillingDonorsOnly;
    	      this.isSwapBillingOnly = defaults.isSwapBillingOnly;
    	      this.sddcId = defaults.sddcId;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder clusterId(@Nullable String clusterId) {

            this.clusterId = clusterId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {

            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder computeInstanceId(@Nullable String computeInstanceId) {

            this.computeInstanceId = computeInstanceId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder esxiHostCollections(List<GetExsiHostsEsxiHostCollection> esxiHostCollections) {
            if (esxiHostCollections == null) {
              throw new MissingRequiredPropertyException("GetExsiHostsResult", "esxiHostCollections");
            }
            this.esxiHostCollections = esxiHostCollections;
            return this;
        }
        public Builder esxiHostCollections(GetExsiHostsEsxiHostCollection... esxiHostCollections) {
            return esxiHostCollections(List.of(esxiHostCollections));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetExsiHostsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetExsiHostsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetExsiHostsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isBillingDonorsOnly(@Nullable Boolean isBillingDonorsOnly) {

            this.isBillingDonorsOnly = isBillingDonorsOnly;
            return this;
        }
        @CustomType.Setter
        public Builder isSwapBillingOnly(@Nullable Boolean isSwapBillingOnly) {

            this.isSwapBillingOnly = isSwapBillingOnly;
            return this;
        }
        @CustomType.Setter
        public Builder sddcId(@Nullable String sddcId) {

            this.sddcId = sddcId;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetExsiHostsResult build() {
            final var _resultValue = new GetExsiHostsResult();
            _resultValue.clusterId = clusterId;
            _resultValue.compartmentId = compartmentId;
            _resultValue.computeInstanceId = computeInstanceId;
            _resultValue.displayName = displayName;
            _resultValue.esxiHostCollections = esxiHostCollections;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.isBillingDonorsOnly = isBillingDonorsOnly;
            _resultValue.isSwapBillingOnly = isSwapBillingOnly;
            _resultValue.sddcId = sddcId;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
