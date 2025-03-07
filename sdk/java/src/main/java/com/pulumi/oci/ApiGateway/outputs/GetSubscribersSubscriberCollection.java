// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApiGateway.outputs.GetSubscribersSubscriberCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSubscribersSubscriberCollection {
    private List<GetSubscribersSubscriberCollectionItem> items;

    private GetSubscribersSubscriberCollection() {}
    public List<GetSubscribersSubscriberCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSubscribersSubscriberCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetSubscribersSubscriberCollectionItem> items;
        public Builder() {}
        public Builder(GetSubscribersSubscriberCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetSubscribersSubscriberCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetSubscribersSubscriberCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetSubscribersSubscriberCollectionItem... items) {
            return items(List.of(items));
        }
        public GetSubscribersSubscriberCollection build() {
            final var _resultValue = new GetSubscribersSubscriberCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
