// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabaseGroupsManagedDatabaseGroupCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetManagedDatabaseGroupsManagedDatabaseGroupCollection {
    private List<GetManagedDatabaseGroupsManagedDatabaseGroupCollectionItem> items;

    private GetManagedDatabaseGroupsManagedDatabaseGroupCollection() {}
    public List<GetManagedDatabaseGroupsManagedDatabaseGroupCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabaseGroupsManagedDatabaseGroupCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetManagedDatabaseGroupsManagedDatabaseGroupCollectionItem> items;
        public Builder() {}
        public Builder(GetManagedDatabaseGroupsManagedDatabaseGroupCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetManagedDatabaseGroupsManagedDatabaseGroupCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetManagedDatabaseGroupsManagedDatabaseGroupCollectionItem... items) {
            return items(List.of(items));
        }
        public GetManagedDatabaseGroupsManagedDatabaseGroupCollection build() {
            final var o = new GetManagedDatabaseGroupsManagedDatabaseGroupCollection();
            o.items = items;
            return o;
        }
    }
}