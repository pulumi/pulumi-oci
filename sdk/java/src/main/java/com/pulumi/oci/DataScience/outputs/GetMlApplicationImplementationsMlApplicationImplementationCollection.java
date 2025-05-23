// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataScience.outputs.GetMlApplicationImplementationsMlApplicationImplementationCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetMlApplicationImplementationsMlApplicationImplementationCollection {
    private List<GetMlApplicationImplementationsMlApplicationImplementationCollectionItem> items;

    private GetMlApplicationImplementationsMlApplicationImplementationCollection() {}
    public List<GetMlApplicationImplementationsMlApplicationImplementationCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMlApplicationImplementationsMlApplicationImplementationCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetMlApplicationImplementationsMlApplicationImplementationCollectionItem> items;
        public Builder() {}
        public Builder(GetMlApplicationImplementationsMlApplicationImplementationCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetMlApplicationImplementationsMlApplicationImplementationCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetMlApplicationImplementationsMlApplicationImplementationCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetMlApplicationImplementationsMlApplicationImplementationCollectionItem... items) {
            return items(List.of(items));
        }
        public GetMlApplicationImplementationsMlApplicationImplementationCollection build() {
            final var _resultValue = new GetMlApplicationImplementationsMlApplicationImplementationCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
