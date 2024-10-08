// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.MediaServices.outputs.GetStreamPackagingConfigsStreamPackagingConfigCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetStreamPackagingConfigsStreamPackagingConfigCollection {
    private List<GetStreamPackagingConfigsStreamPackagingConfigCollectionItem> items;

    private GetStreamPackagingConfigsStreamPackagingConfigCollection() {}
    public List<GetStreamPackagingConfigsStreamPackagingConfigCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetStreamPackagingConfigsStreamPackagingConfigCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetStreamPackagingConfigsStreamPackagingConfigCollectionItem> items;
        public Builder() {}
        public Builder(GetStreamPackagingConfigsStreamPackagingConfigCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetStreamPackagingConfigsStreamPackagingConfigCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetStreamPackagingConfigsStreamPackagingConfigCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetStreamPackagingConfigsStreamPackagingConfigCollectionItem... items) {
            return items(List.of(items));
        }
        public GetStreamPackagingConfigsStreamPackagingConfigCollection build() {
            final var _resultValue = new GetStreamPackagingConfigsStreamPackagingConfigCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
