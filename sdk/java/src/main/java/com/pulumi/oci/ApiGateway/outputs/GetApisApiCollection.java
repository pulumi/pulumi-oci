// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.GetApisApiCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetApisApiCollection {
    private List<GetApisApiCollectionItem> items;

    private GetApisApiCollection() {}
    public List<GetApisApiCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetApisApiCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetApisApiCollectionItem> items;
        public Builder() {}
        public Builder(GetApisApiCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetApisApiCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetApisApiCollectionItem... items) {
            return items(List.of(items));
        }
        public GetApisApiCollection build() {
            final var o = new GetApisApiCollection();
            o.items = items;
            return o;
        }
    }
}