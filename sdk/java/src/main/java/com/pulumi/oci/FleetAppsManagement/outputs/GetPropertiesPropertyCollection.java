// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.GetPropertiesPropertyCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetPropertiesPropertyCollection {
    private List<GetPropertiesPropertyCollectionItem> items;

    private GetPropertiesPropertyCollection() {}
    public List<GetPropertiesPropertyCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPropertiesPropertyCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetPropertiesPropertyCollectionItem> items;
        public Builder() {}
        public Builder(GetPropertiesPropertyCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetPropertiesPropertyCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetPropertiesPropertyCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetPropertiesPropertyCollectionItem... items) {
            return items(List.of(items));
        }
        public GetPropertiesPropertyCollection build() {
            final var _resultValue = new GetPropertiesPropertyCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
