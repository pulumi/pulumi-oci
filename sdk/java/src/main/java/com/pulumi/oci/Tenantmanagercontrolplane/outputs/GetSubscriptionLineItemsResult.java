// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Tenantmanagercontrolplane.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Tenantmanagercontrolplane.outputs.GetSubscriptionLineItemsFilter;
import com.pulumi.oci.Tenantmanagercontrolplane.outputs.GetSubscriptionLineItemsSubscriptionLineItemCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetSubscriptionLineItemsResult {
    private @Nullable List<GetSubscriptionLineItemsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String subscriptionId;
    /**
     * @return The list of subscription_line_item_collection.
     * 
     */
    private List<GetSubscriptionLineItemsSubscriptionLineItemCollection> subscriptionLineItemCollections;

    private GetSubscriptionLineItemsResult() {}
    public List<GetSubscriptionLineItemsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String subscriptionId() {
        return this.subscriptionId;
    }
    /**
     * @return The list of subscription_line_item_collection.
     * 
     */
    public List<GetSubscriptionLineItemsSubscriptionLineItemCollection> subscriptionLineItemCollections() {
        return this.subscriptionLineItemCollections;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSubscriptionLineItemsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<GetSubscriptionLineItemsFilter> filters;
        private String id;
        private String subscriptionId;
        private List<GetSubscriptionLineItemsSubscriptionLineItemCollection> subscriptionLineItemCollections;
        public Builder() {}
        public Builder(GetSubscriptionLineItemsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.subscriptionId = defaults.subscriptionId;
    	      this.subscriptionLineItemCollections = defaults.subscriptionLineItemCollections;
        }

        @CustomType.Setter
        public Builder filters(@Nullable List<GetSubscriptionLineItemsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetSubscriptionLineItemsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionLineItemsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder subscriptionId(String subscriptionId) {
            if (subscriptionId == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionLineItemsResult", "subscriptionId");
            }
            this.subscriptionId = subscriptionId;
            return this;
        }
        @CustomType.Setter
        public Builder subscriptionLineItemCollections(List<GetSubscriptionLineItemsSubscriptionLineItemCollection> subscriptionLineItemCollections) {
            if (subscriptionLineItemCollections == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionLineItemsResult", "subscriptionLineItemCollections");
            }
            this.subscriptionLineItemCollections = subscriptionLineItemCollections;
            return this;
        }
        public Builder subscriptionLineItemCollections(GetSubscriptionLineItemsSubscriptionLineItemCollection... subscriptionLineItemCollections) {
            return subscriptionLineItemCollections(List.of(subscriptionLineItemCollections));
        }
        public GetSubscriptionLineItemsResult build() {
            final var _resultValue = new GetSubscriptionLineItemsResult();
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.subscriptionId = subscriptionId;
            _resultValue.subscriptionLineItemCollections = subscriptionLineItemCollections;
            return _resultValue;
        }
    }
}
