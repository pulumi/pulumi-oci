// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.GetAppCatalogListingResourceVersionsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAppCatalogListingResourceVersionsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAppCatalogListingResourceVersionsPlainArgs Empty = new GetAppCatalogListingResourceVersionsPlainArgs();

    @Import(name="filters")
    private @Nullable List<GetAppCatalogListingResourceVersionsFilter> filters;

    public Optional<List<GetAppCatalogListingResourceVersionsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The OCID of the listing.
     * 
     */
    @Import(name="listingId", required=true)
    private String listingId;

    /**
     * @return The OCID of the listing.
     * 
     */
    public String listingId() {
        return this.listingId;
    }

    private GetAppCatalogListingResourceVersionsPlainArgs() {}

    private GetAppCatalogListingResourceVersionsPlainArgs(GetAppCatalogListingResourceVersionsPlainArgs $) {
        this.filters = $.filters;
        this.listingId = $.listingId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAppCatalogListingResourceVersionsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAppCatalogListingResourceVersionsPlainArgs $;

        public Builder() {
            $ = new GetAppCatalogListingResourceVersionsPlainArgs();
        }

        public Builder(GetAppCatalogListingResourceVersionsPlainArgs defaults) {
            $ = new GetAppCatalogListingResourceVersionsPlainArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable List<GetAppCatalogListingResourceVersionsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetAppCatalogListingResourceVersionsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param listingId The OCID of the listing.
         * 
         * @return builder
         * 
         */
        public Builder listingId(String listingId) {
            $.listingId = listingId;
            return this;
        }

        public GetAppCatalogListingResourceVersionsPlainArgs build() {
            $.listingId = Objects.requireNonNull($.listingId, "expected parameter 'listingId' to be non-null");
            return $;
        }
    }

}