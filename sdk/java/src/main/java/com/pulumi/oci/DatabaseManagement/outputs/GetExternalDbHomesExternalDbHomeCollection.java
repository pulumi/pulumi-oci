// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalDbHomesExternalDbHomeCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetExternalDbHomesExternalDbHomeCollection {
    private List<GetExternalDbHomesExternalDbHomeCollectionItem> items;

    private GetExternalDbHomesExternalDbHomeCollection() {}
    public List<GetExternalDbHomesExternalDbHomeCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalDbHomesExternalDbHomeCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetExternalDbHomesExternalDbHomeCollectionItem> items;
        public Builder() {}
        public Builder(GetExternalDbHomesExternalDbHomeCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetExternalDbHomesExternalDbHomeCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetExternalDbHomesExternalDbHomeCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetExternalDbHomesExternalDbHomeCollectionItem... items) {
            return items(List.of(items));
        }
        public GetExternalDbHomesExternalDbHomeCollection build() {
            final var _resultValue = new GetExternalDbHomesExternalDbHomeCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
