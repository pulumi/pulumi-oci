// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OspGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.OspGateway.outputs.GetInvoicesInvoiceCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetInvoicesInvoiceCollection {
    private List<GetInvoicesInvoiceCollectionItem> items;

    private GetInvoicesInvoiceCollection() {}
    public List<GetInvoicesInvoiceCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInvoicesInvoiceCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetInvoicesInvoiceCollectionItem> items;
        public Builder() {}
        public Builder(GetInvoicesInvoiceCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetInvoicesInvoiceCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetInvoicesInvoiceCollectionItem... items) {
            return items(List.of(items));
        }
        public GetInvoicesInvoiceCollection build() {
            final var o = new GetInvoicesInvoiceCollection();
            o.items = items;
            return o;
        }
    }
}