// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opensearch.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Opensearch.outputs.GetOpensearchClustersOpensearchClusterCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetOpensearchClustersOpensearchClusterCollection {
    private List<GetOpensearchClustersOpensearchClusterCollectionItem> items;

    private GetOpensearchClustersOpensearchClusterCollection() {}
    public List<GetOpensearchClustersOpensearchClusterCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetOpensearchClustersOpensearchClusterCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetOpensearchClustersOpensearchClusterCollectionItem> items;
        public Builder() {}
        public Builder(GetOpensearchClustersOpensearchClusterCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetOpensearchClustersOpensearchClusterCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetOpensearchClustersOpensearchClusterCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetOpensearchClustersOpensearchClusterCollectionItem... items) {
            return items(List.of(items));
        }
        public GetOpensearchClustersOpensearchClusterCollection build() {
            final var _resultValue = new GetOpensearchClustersOpensearchClusterCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
