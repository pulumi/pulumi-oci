// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkLoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.NetworkLoadBalancer.outputs.GetBackendSetsBackendSetCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetBackendSetsBackendSetCollection {
    private final List<GetBackendSetsBackendSetCollectionItem> items;

    @CustomType.Constructor
    private GetBackendSetsBackendSetCollection(@CustomType.Parameter("items") List<GetBackendSetsBackendSetCollectionItem> items) {
        this.items = items;
    }

    public List<GetBackendSetsBackendSetCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBackendSetsBackendSetCollection defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetBackendSetsBackendSetCollectionItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(GetBackendSetsBackendSetCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(List<GetBackendSetsBackendSetCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetBackendSetsBackendSetCollectionItem... items) {
            return items(List.of(items));
        }        public GetBackendSetsBackendSetCollection build() {
            return new GetBackendSetsBackendSetCollection(items);
        }
    }
}
