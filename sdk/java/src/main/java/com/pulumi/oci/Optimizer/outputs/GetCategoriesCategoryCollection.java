// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Optimizer.outputs.GetCategoriesCategoryCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetCategoriesCategoryCollection {
    private List<GetCategoriesCategoryCollectionItem> items;

    private GetCategoriesCategoryCollection() {}
    public List<GetCategoriesCategoryCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCategoriesCategoryCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetCategoriesCategoryCollectionItem> items;
        public Builder() {}
        public Builder(GetCategoriesCategoryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetCategoriesCategoryCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetCategoriesCategoryCollectionItem... items) {
            return items(List.of(items));
        }
        public GetCategoriesCategoryCollection build() {
            final var o = new GetCategoriesCategoryCollection();
            o.items = items;
            return o;
        }
    }
}