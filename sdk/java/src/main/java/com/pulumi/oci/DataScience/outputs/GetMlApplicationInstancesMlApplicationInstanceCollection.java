// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataScience.outputs.GetMlApplicationInstancesMlApplicationInstanceCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetMlApplicationInstancesMlApplicationInstanceCollection {
    private List<GetMlApplicationInstancesMlApplicationInstanceCollectionItem> items;

    private GetMlApplicationInstancesMlApplicationInstanceCollection() {}
    public List<GetMlApplicationInstancesMlApplicationInstanceCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMlApplicationInstancesMlApplicationInstanceCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetMlApplicationInstancesMlApplicationInstanceCollectionItem> items;
        public Builder() {}
        public Builder(GetMlApplicationInstancesMlApplicationInstanceCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetMlApplicationInstancesMlApplicationInstanceCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetMlApplicationInstancesMlApplicationInstanceCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetMlApplicationInstancesMlApplicationInstanceCollectionItem... items) {
            return items(List.of(items));
        }
        public GetMlApplicationInstancesMlApplicationInstanceCollection build() {
            final var _resultValue = new GetMlApplicationInstancesMlApplicationInstanceCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
