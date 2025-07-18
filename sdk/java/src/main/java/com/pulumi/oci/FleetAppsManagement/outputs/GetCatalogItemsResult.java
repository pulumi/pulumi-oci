// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.GetCatalogItemsCatalogItemCollection;
import com.pulumi.oci.FleetAppsManagement.outputs.GetCatalogItemsFilter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetCatalogItemsResult {
    /**
     * @return The list of catalog_item_collection.
     * 
     */
    private List<GetCatalogItemsCatalogItemCollection> catalogItemCollections;
    private @Nullable String catalogListingId;
    private @Nullable String catalogListingVersionCriteria;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return Config source type Eg: STACK_TEMPLATE_CATALOG_SOURCE, PAR_CATALOG_SOURCE, GIT_CATALOG_SOURCE, MARKETPLACE_CATALOG_SOURCE.
     * 
     */
    private @Nullable String configSourceType;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetCatalogItemsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The indicator to append Public Items from the root compartment to any query, when set to TRUE.
     * 
     */
    private @Nullable Boolean shouldListPublicItems;
    /**
     * @return The current state of the CatalogItem.
     * 
     */
    private @Nullable String state;

    private GetCatalogItemsResult() {}
    /**
     * @return The list of catalog_item_collection.
     * 
     */
    public List<GetCatalogItemsCatalogItemCollection> catalogItemCollections() {
        return this.catalogItemCollections;
    }
    public Optional<String> catalogListingId() {
        return Optional.ofNullable(this.catalogListingId);
    }
    public Optional<String> catalogListingVersionCriteria() {
        return Optional.ofNullable(this.catalogListingVersionCriteria);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Config source type Eg: STACK_TEMPLATE_CATALOG_SOURCE, PAR_CATALOG_SOURCE, GIT_CATALOG_SOURCE, MARKETPLACE_CATALOG_SOURCE.
     * 
     */
    public Optional<String> configSourceType() {
        return Optional.ofNullable(this.configSourceType);
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetCatalogItemsFilter> filters() {
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
     * @return The indicator to append Public Items from the root compartment to any query, when set to TRUE.
     * 
     */
    public Optional<Boolean> shouldListPublicItems() {
        return Optional.ofNullable(this.shouldListPublicItems);
    }
    /**
     * @return The current state of the CatalogItem.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCatalogItemsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetCatalogItemsCatalogItemCollection> catalogItemCollections;
        private @Nullable String catalogListingId;
        private @Nullable String catalogListingVersionCriteria;
        private String compartmentId;
        private @Nullable String configSourceType;
        private @Nullable String displayName;
        private @Nullable List<GetCatalogItemsFilter> filters;
        private String id;
        private @Nullable Boolean shouldListPublicItems;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetCatalogItemsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.catalogItemCollections = defaults.catalogItemCollections;
    	      this.catalogListingId = defaults.catalogListingId;
    	      this.catalogListingVersionCriteria = defaults.catalogListingVersionCriteria;
    	      this.compartmentId = defaults.compartmentId;
    	      this.configSourceType = defaults.configSourceType;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.shouldListPublicItems = defaults.shouldListPublicItems;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder catalogItemCollections(List<GetCatalogItemsCatalogItemCollection> catalogItemCollections) {
            if (catalogItemCollections == null) {
              throw new MissingRequiredPropertyException("GetCatalogItemsResult", "catalogItemCollections");
            }
            this.catalogItemCollections = catalogItemCollections;
            return this;
        }
        public Builder catalogItemCollections(GetCatalogItemsCatalogItemCollection... catalogItemCollections) {
            return catalogItemCollections(List.of(catalogItemCollections));
        }
        @CustomType.Setter
        public Builder catalogListingId(@Nullable String catalogListingId) {

            this.catalogListingId = catalogListingId;
            return this;
        }
        @CustomType.Setter
        public Builder catalogListingVersionCriteria(@Nullable String catalogListingVersionCriteria) {

            this.catalogListingVersionCriteria = catalogListingVersionCriteria;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetCatalogItemsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder configSourceType(@Nullable String configSourceType) {

            this.configSourceType = configSourceType;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetCatalogItemsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetCatalogItemsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetCatalogItemsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder shouldListPublicItems(@Nullable Boolean shouldListPublicItems) {

            this.shouldListPublicItems = shouldListPublicItems;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetCatalogItemsResult build() {
            final var _resultValue = new GetCatalogItemsResult();
            _resultValue.catalogItemCollections = catalogItemCollections;
            _resultValue.catalogListingId = catalogListingId;
            _resultValue.catalogListingVersionCriteria = catalogListingVersionCriteria;
            _resultValue.compartmentId = compartmentId;
            _resultValue.configSourceType = configSourceType;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.shouldListPublicItems = shouldListPublicItems;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
