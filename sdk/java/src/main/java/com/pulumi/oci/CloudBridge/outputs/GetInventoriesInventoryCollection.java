// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudBridge.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudBridge.outputs.GetInventoriesInventoryCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetInventoriesInventoryCollection {
    private List<GetInventoriesInventoryCollectionItem> items;

    private GetInventoriesInventoryCollection() {}
    public List<GetInventoriesInventoryCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInventoriesInventoryCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetInventoriesInventoryCollectionItem> items;
        public Builder() {}
        public Builder(GetInventoriesInventoryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetInventoriesInventoryCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetInventoriesInventoryCollectionItem... items) {
            return items(List.of(items));
        }
        public GetInventoriesInventoryCollection build() {
            final var o = new GetInventoriesInventoryCollection();
            o.items = items;
            return o;
        }
    }
}