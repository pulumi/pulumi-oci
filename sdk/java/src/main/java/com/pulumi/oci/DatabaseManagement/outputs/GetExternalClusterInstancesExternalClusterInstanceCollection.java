// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalClusterInstancesExternalClusterInstanceCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetExternalClusterInstancesExternalClusterInstanceCollection {
    private List<GetExternalClusterInstancesExternalClusterInstanceCollectionItem> items;

    private GetExternalClusterInstancesExternalClusterInstanceCollection() {}
    public List<GetExternalClusterInstancesExternalClusterInstanceCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalClusterInstancesExternalClusterInstanceCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetExternalClusterInstancesExternalClusterInstanceCollectionItem> items;
        public Builder() {}
        public Builder(GetExternalClusterInstancesExternalClusterInstanceCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetExternalClusterInstancesExternalClusterInstanceCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetExternalClusterInstancesExternalClusterInstanceCollectionItem... items) {
            return items(List.of(items));
        }
        public GetExternalClusterInstancesExternalClusterInstanceCollection build() {
            final var o = new GetExternalClusterInstancesExternalClusterInstanceCollection();
            o.items = items;
            return o;
        }
    }
}