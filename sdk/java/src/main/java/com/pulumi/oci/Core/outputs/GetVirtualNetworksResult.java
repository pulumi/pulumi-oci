// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetVirtualNetworksFilter;
import com.pulumi.oci.Core.outputs.GetVirtualNetworksVirtualNetwork;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetVirtualNetworksResult {
    private String compartmentId;
    private @Nullable String displayName;
    private @Nullable List<GetVirtualNetworksFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable String state;
    private List<GetVirtualNetworksVirtualNetwork> virtualNetworks;

    private GetVirtualNetworksResult() {}
    public String compartmentId() {
        return this.compartmentId;
    }
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetVirtualNetworksFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    public List<GetVirtualNetworksVirtualNetwork> virtualNetworks() {
        return this.virtualNetworks;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVirtualNetworksResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetVirtualNetworksFilter> filters;
        private String id;
        private @Nullable String state;
        private List<GetVirtualNetworksVirtualNetwork> virtualNetworks;
        public Builder() {}
        public Builder(GetVirtualNetworksResult defaults) {
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
        public Builder filters(@Nullable List<GetVirtualNetworksFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetVirtualNetworksFilter... filters) {
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
        public Builder virtualNetworks(List<GetVirtualNetworksVirtualNetwork> virtualNetworks) {
            this.virtualNetworks = Objects.requireNonNull(virtualNetworks);
            return this;
        }
        public Builder virtualNetworks(GetVirtualNetworksVirtualNetwork... virtualNetworks) {
            return virtualNetworks(List.of(virtualNetworks));
        }
        public GetVirtualNetworksResult build() {
            final var o = new GetVirtualNetworksResult();
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