// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetDbManagementPrivateEndpointsDbManagementPrivateEndpointCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDbManagementPrivateEndpointsDbManagementPrivateEndpointCollection {
    private List<GetDbManagementPrivateEndpointsDbManagementPrivateEndpointCollectionItem> items;

    private GetDbManagementPrivateEndpointsDbManagementPrivateEndpointCollection() {}
    public List<GetDbManagementPrivateEndpointsDbManagementPrivateEndpointCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDbManagementPrivateEndpointsDbManagementPrivateEndpointCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDbManagementPrivateEndpointsDbManagementPrivateEndpointCollectionItem> items;
        public Builder() {}
        public Builder(GetDbManagementPrivateEndpointsDbManagementPrivateEndpointCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetDbManagementPrivateEndpointsDbManagementPrivateEndpointCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetDbManagementPrivateEndpointsDbManagementPrivateEndpointCollectionItem... items) {
            return items(List.of(items));
        }
        public GetDbManagementPrivateEndpointsDbManagementPrivateEndpointCollection build() {
            final var o = new GetDbManagementPrivateEndpointsDbManagementPrivateEndpointCollection();
            o.items = items;
            return o;
        }
    }
}