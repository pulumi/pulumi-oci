// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetAppCatalogSubscriptionsAppCatalogSubscription;
import com.pulumi.oci.Core.outputs.GetAppCatalogSubscriptionsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetAppCatalogSubscriptionsResult {
    /**
     * @return The list of app_catalog_subscriptions.
     * 
     */
    private List<GetAppCatalogSubscriptionsAppCatalogSubscription> appCatalogSubscriptions;
    /**
     * @return The compartmentID of the subscription.
     * 
     */
    private String compartmentId;
    private @Nullable List<GetAppCatalogSubscriptionsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The ocid of the listing resource.
     * 
     */
    private @Nullable String listingId;

    private GetAppCatalogSubscriptionsResult() {}
    /**
     * @return The list of app_catalog_subscriptions.
     * 
     */
    public List<GetAppCatalogSubscriptionsAppCatalogSubscription> appCatalogSubscriptions() {
        return this.appCatalogSubscriptions;
    }
    /**
     * @return The compartmentID of the subscription.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetAppCatalogSubscriptionsFilter> filters() {
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
     * @return The ocid of the listing resource.
     * 
     */
    public Optional<String> listingId() {
        return Optional.ofNullable(this.listingId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAppCatalogSubscriptionsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetAppCatalogSubscriptionsAppCatalogSubscription> appCatalogSubscriptions;
        private String compartmentId;
        private @Nullable List<GetAppCatalogSubscriptionsFilter> filters;
        private String id;
        private @Nullable String listingId;
        public Builder() {}
        public Builder(GetAppCatalogSubscriptionsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.appCatalogSubscriptions = defaults.appCatalogSubscriptions;
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.listingId = defaults.listingId;
        }

        @CustomType.Setter
        public Builder appCatalogSubscriptions(List<GetAppCatalogSubscriptionsAppCatalogSubscription> appCatalogSubscriptions) {
            this.appCatalogSubscriptions = Objects.requireNonNull(appCatalogSubscriptions);
            return this;
        }
        public Builder appCatalogSubscriptions(GetAppCatalogSubscriptionsAppCatalogSubscription... appCatalogSubscriptions) {
            return appCatalogSubscriptions(List.of(appCatalogSubscriptions));
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetAppCatalogSubscriptionsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetAppCatalogSubscriptionsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder listingId(@Nullable String listingId) {
            this.listingId = listingId;
            return this;
        }
        public GetAppCatalogSubscriptionsResult build() {
            final var o = new GetAppCatalogSubscriptionsResult();
            o.appCatalogSubscriptions = appCatalogSubscriptions;
            o.compartmentId = compartmentId;
            o.filters = filters;
            o.id = id;
            o.listingId = listingId;
            return o;
        }
    }
}