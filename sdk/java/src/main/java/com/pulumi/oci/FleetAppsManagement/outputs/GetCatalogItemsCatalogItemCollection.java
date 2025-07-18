// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.GetCatalogItemsCatalogItemCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetCatalogItemsCatalogItemCollection {
    private List<GetCatalogItemsCatalogItemCollectionItem> items;

    private GetCatalogItemsCatalogItemCollection() {}
    public List<GetCatalogItemsCatalogItemCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCatalogItemsCatalogItemCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetCatalogItemsCatalogItemCollectionItem> items;
        public Builder() {}
        public Builder(GetCatalogItemsCatalogItemCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetCatalogItemsCatalogItemCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetCatalogItemsCatalogItemCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetCatalogItemsCatalogItemCollectionItem... items) {
            return items(List.of(items));
        }
        public GetCatalogItemsCatalogItemCollection build() {
            final var _resultValue = new GetCatalogItemsCatalogItemCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
