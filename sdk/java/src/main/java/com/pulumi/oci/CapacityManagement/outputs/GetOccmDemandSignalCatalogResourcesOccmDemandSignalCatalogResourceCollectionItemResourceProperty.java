// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CapacityManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CapacityManagement.outputs.GetOccmDemandSignalCatalogResourcesOccmDemandSignalCatalogResourceCollectionItemResourcePropertyItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetOccmDemandSignalCatalogResourcesOccmDemandSignalCatalogResourceCollectionItemResourceProperty {
    /**
     * @return An array of items containing detailed information about a resource&#39;s property dependecies.
     * 
     */
    private List<GetOccmDemandSignalCatalogResourcesOccmDemandSignalCatalogResourceCollectionItemResourcePropertyItem> items;

    private GetOccmDemandSignalCatalogResourcesOccmDemandSignalCatalogResourceCollectionItemResourceProperty() {}
    /**
     * @return An array of items containing detailed information about a resource&#39;s property dependecies.
     * 
     */
    public List<GetOccmDemandSignalCatalogResourcesOccmDemandSignalCatalogResourceCollectionItemResourcePropertyItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetOccmDemandSignalCatalogResourcesOccmDemandSignalCatalogResourceCollectionItemResourceProperty defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetOccmDemandSignalCatalogResourcesOccmDemandSignalCatalogResourceCollectionItemResourcePropertyItem> items;
        public Builder() {}
        public Builder(GetOccmDemandSignalCatalogResourcesOccmDemandSignalCatalogResourceCollectionItemResourceProperty defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetOccmDemandSignalCatalogResourcesOccmDemandSignalCatalogResourceCollectionItemResourcePropertyItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetOccmDemandSignalCatalogResourcesOccmDemandSignalCatalogResourceCollectionItemResourceProperty", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetOccmDemandSignalCatalogResourcesOccmDemandSignalCatalogResourceCollectionItemResourcePropertyItem... items) {
            return items(List.of(items));
        }
        public GetOccmDemandSignalCatalogResourcesOccmDemandSignalCatalogResourceCollectionItemResourceProperty build() {
            final var _resultValue = new GetOccmDemandSignalCatalogResourcesOccmDemandSignalCatalogResourceCollectionItemResourceProperty();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
