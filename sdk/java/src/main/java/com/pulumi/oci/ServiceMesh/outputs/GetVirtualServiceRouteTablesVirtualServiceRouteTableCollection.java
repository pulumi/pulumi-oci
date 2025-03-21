// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ServiceMesh.outputs.GetVirtualServiceRouteTablesVirtualServiceRouteTableCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetVirtualServiceRouteTablesVirtualServiceRouteTableCollection {
    private List<GetVirtualServiceRouteTablesVirtualServiceRouteTableCollectionItem> items;

    private GetVirtualServiceRouteTablesVirtualServiceRouteTableCollection() {}
    public List<GetVirtualServiceRouteTablesVirtualServiceRouteTableCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVirtualServiceRouteTablesVirtualServiceRouteTableCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetVirtualServiceRouteTablesVirtualServiceRouteTableCollectionItem> items;
        public Builder() {}
        public Builder(GetVirtualServiceRouteTablesVirtualServiceRouteTableCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetVirtualServiceRouteTablesVirtualServiceRouteTableCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetVirtualServiceRouteTablesVirtualServiceRouteTableCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetVirtualServiceRouteTablesVirtualServiceRouteTableCollectionItem... items) {
            return items(List.of(items));
        }
        public GetVirtualServiceRouteTablesVirtualServiceRouteTableCollection build() {
            final var _resultValue = new GetVirtualServiceRouteTablesVirtualServiceRouteTableCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
