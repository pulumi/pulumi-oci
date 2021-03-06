// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetAppCatalogListingResourceVersionsAppCatalogListingResourceVersion;
import com.pulumi.oci.Core.outputs.GetAppCatalogListingResourceVersionsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetAppCatalogListingResourceVersionsResult {
    /**
     * @return The list of app_catalog_listing_resource_versions.
     * 
     */
    private final List<GetAppCatalogListingResourceVersionsAppCatalogListingResourceVersion> appCatalogListingResourceVersions;
    private final @Nullable List<GetAppCatalogListingResourceVersionsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The OCID of the listing this resource version belongs to.
     * 
     */
    private final String listingId;

    @CustomType.Constructor
    private GetAppCatalogListingResourceVersionsResult(
        @CustomType.Parameter("appCatalogListingResourceVersions") List<GetAppCatalogListingResourceVersionsAppCatalogListingResourceVersion> appCatalogListingResourceVersions,
        @CustomType.Parameter("filters") @Nullable List<GetAppCatalogListingResourceVersionsFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("listingId") String listingId) {
        this.appCatalogListingResourceVersions = appCatalogListingResourceVersions;
        this.filters = filters;
        this.id = id;
        this.listingId = listingId;
    }

    /**
     * @return The list of app_catalog_listing_resource_versions.
     * 
     */
    public List<GetAppCatalogListingResourceVersionsAppCatalogListingResourceVersion> appCatalogListingResourceVersions() {
        return this.appCatalogListingResourceVersions;
    }
    public List<GetAppCatalogListingResourceVersionsFilter> filters() {
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
     * @return The OCID of the listing this resource version belongs to.
     * 
     */
    public String listingId() {
        return this.listingId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAppCatalogListingResourceVersionsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetAppCatalogListingResourceVersionsAppCatalogListingResourceVersion> appCatalogListingResourceVersions;
        private @Nullable List<GetAppCatalogListingResourceVersionsFilter> filters;
        private String id;
        private String listingId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetAppCatalogListingResourceVersionsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.appCatalogListingResourceVersions = defaults.appCatalogListingResourceVersions;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.listingId = defaults.listingId;
        }

        public Builder appCatalogListingResourceVersions(List<GetAppCatalogListingResourceVersionsAppCatalogListingResourceVersion> appCatalogListingResourceVersions) {
            this.appCatalogListingResourceVersions = Objects.requireNonNull(appCatalogListingResourceVersions);
            return this;
        }
        public Builder appCatalogListingResourceVersions(GetAppCatalogListingResourceVersionsAppCatalogListingResourceVersion... appCatalogListingResourceVersions) {
            return appCatalogListingResourceVersions(List.of(appCatalogListingResourceVersions));
        }
        public Builder filters(@Nullable List<GetAppCatalogListingResourceVersionsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetAppCatalogListingResourceVersionsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder listingId(String listingId) {
            this.listingId = Objects.requireNonNull(listingId);
            return this;
        }        public GetAppCatalogListingResourceVersionsResult build() {
            return new GetAppCatalogListingResourceVersionsResult(appCatalogListingResourceVersions, filters, id, listingId);
        }
    }
}
