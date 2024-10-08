// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.outputs.GetComputeCapacityTopologyComputeBareMetalHostsComputeBareMetalHostCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetComputeCapacityTopologyComputeBareMetalHostsComputeBareMetalHostCollection {
    /**
     * @return The list of compute bare metal hosts.
     * 
     */
    private List<GetComputeCapacityTopologyComputeBareMetalHostsComputeBareMetalHostCollectionItem> items;

    private GetComputeCapacityTopologyComputeBareMetalHostsComputeBareMetalHostCollection() {}
    /**
     * @return The list of compute bare metal hosts.
     * 
     */
    public List<GetComputeCapacityTopologyComputeBareMetalHostsComputeBareMetalHostCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetComputeCapacityTopologyComputeBareMetalHostsComputeBareMetalHostCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetComputeCapacityTopologyComputeBareMetalHostsComputeBareMetalHostCollectionItem> items;
        public Builder() {}
        public Builder(GetComputeCapacityTopologyComputeBareMetalHostsComputeBareMetalHostCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetComputeCapacityTopologyComputeBareMetalHostsComputeBareMetalHostCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetComputeCapacityTopologyComputeBareMetalHostsComputeBareMetalHostCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetComputeCapacityTopologyComputeBareMetalHostsComputeBareMetalHostCollectionItem... items) {
            return items(List.of(items));
        }
        public GetComputeCapacityTopologyComputeBareMetalHostsComputeBareMetalHostCollection build() {
            final var _resultValue = new GetComputeCapacityTopologyComputeBareMetalHostsComputeBareMetalHostCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
