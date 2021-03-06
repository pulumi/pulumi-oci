// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceCatalog.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ServiceCatalog.outputs.GetServiceCatalogsServiceCatalogCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetServiceCatalogsServiceCatalogCollection {
    private final List<GetServiceCatalogsServiceCatalogCollectionItem> items;

    @CustomType.Constructor
    private GetServiceCatalogsServiceCatalogCollection(@CustomType.Parameter("items") List<GetServiceCatalogsServiceCatalogCollectionItem> items) {
        this.items = items;
    }

    public List<GetServiceCatalogsServiceCatalogCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetServiceCatalogsServiceCatalogCollection defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetServiceCatalogsServiceCatalogCollectionItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(GetServiceCatalogsServiceCatalogCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(List<GetServiceCatalogsServiceCatalogCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetServiceCatalogsServiceCatalogCollectionItem... items) {
            return items(List.of(items));
        }        public GetServiceCatalogsServiceCatalogCollection build() {
            return new GetServiceCatalogsServiceCatalogCollection(items);
        }
    }
}
