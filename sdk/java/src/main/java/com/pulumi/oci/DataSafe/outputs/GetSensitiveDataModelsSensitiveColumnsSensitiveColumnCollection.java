// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetSensitiveDataModelsSensitiveColumnsSensitiveColumnCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSensitiveDataModelsSensitiveColumnsSensitiveColumnCollection {
    private List<GetSensitiveDataModelsSensitiveColumnsSensitiveColumnCollectionItem> items;

    private GetSensitiveDataModelsSensitiveColumnsSensitiveColumnCollection() {}
    public List<GetSensitiveDataModelsSensitiveColumnsSensitiveColumnCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSensitiveDataModelsSensitiveColumnsSensitiveColumnCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetSensitiveDataModelsSensitiveColumnsSensitiveColumnCollectionItem> items;
        public Builder() {}
        public Builder(GetSensitiveDataModelsSensitiveColumnsSensitiveColumnCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetSensitiveDataModelsSensitiveColumnsSensitiveColumnCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetSensitiveDataModelsSensitiveColumnsSensitiveColumnCollectionItem... items) {
            return items(List.of(items));
        }
        public GetSensitiveDataModelsSensitiveColumnsSensitiveColumnCollection build() {
            final var o = new GetSensitiveDataModelsSensitiveColumnsSensitiveColumnCollection();
            o.items = items;
            return o;
        }
    }
}