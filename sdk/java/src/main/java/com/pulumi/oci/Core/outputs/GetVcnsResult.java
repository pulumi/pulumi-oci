// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetVcnsFilter;
import com.pulumi.oci.Core.outputs.GetVcnsVirtualNetwork;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetVcnsResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the VCN.
     * 
     */
    private String compartmentId;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetVcnsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The VCN&#39;s current state.
     * 
     */
    private @Nullable String state;
    /**
     * @return The list of virtual_networks.
     * 
     */
    private List<GetVcnsVirtualNetwork> virtualNetworks;

    private GetVcnsResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the VCN.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetVcnsFilter> filters() {
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
     * @return The VCN&#39;s current state.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The list of virtual_networks.
     * 
     */
    public List<GetVcnsVirtualNetwork> virtualNetworks() {
        return this.virtualNetworks;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVcnsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetVcnsFilter> filters;
        private String id;
        private @Nullable String state;
        private List<GetVcnsVirtualNetwork> virtualNetworks;
        public Builder() {}
        public Builder(GetVcnsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
    	      this.virtualNetworks = defaults.virtualNetworks;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetVcnsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetVcnsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder virtualNetworks(List<GetVcnsVirtualNetwork> virtualNetworks) {
            this.virtualNetworks = Objects.requireNonNull(virtualNetworks);
            return this;
        }
        public Builder virtualNetworks(GetVcnsVirtualNetwork... virtualNetworks) {
            return virtualNetworks(List.of(virtualNetworks));
        }
        public GetVcnsResult build() {
            final var o = new GetVcnsResult();
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.filters = filters;
            o.id = id;
            o.state = state;
            o.virtualNetworks = virtualNetworks;
            return o;
        }
    }
}