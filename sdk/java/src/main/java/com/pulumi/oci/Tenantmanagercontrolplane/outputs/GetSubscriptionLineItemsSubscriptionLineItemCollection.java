// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Tenantmanagercontrolplane.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Tenantmanagercontrolplane.outputs.GetSubscriptionLineItemsSubscriptionLineItemCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSubscriptionLineItemsSubscriptionLineItemCollection {
    /**
     * @return Array containing line item summaries in a subscription.
     * 
     */
    private List<GetSubscriptionLineItemsSubscriptionLineItemCollectionItem> items;

    private GetSubscriptionLineItemsSubscriptionLineItemCollection() {}
    /**
     * @return Array containing line item summaries in a subscription.
     * 
     */
    public List<GetSubscriptionLineItemsSubscriptionLineItemCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSubscriptionLineItemsSubscriptionLineItemCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetSubscriptionLineItemsSubscriptionLineItemCollectionItem> items;
        public Builder() {}
        public Builder(GetSubscriptionLineItemsSubscriptionLineItemCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetSubscriptionLineItemsSubscriptionLineItemCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionLineItemsSubscriptionLineItemCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetSubscriptionLineItemsSubscriptionLineItemCollectionItem... items) {
            return items(List.of(items));
        }
        public GetSubscriptionLineItemsSubscriptionLineItemCollection build() {
            final var _resultValue = new GetSubscriptionLineItemsSubscriptionLineItemCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
