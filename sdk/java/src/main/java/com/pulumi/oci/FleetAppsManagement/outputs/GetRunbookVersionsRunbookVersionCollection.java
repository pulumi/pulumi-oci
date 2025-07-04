// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.GetRunbookVersionsRunbookVersionCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetRunbookVersionsRunbookVersionCollection {
    private List<GetRunbookVersionsRunbookVersionCollectionItem> items;

    private GetRunbookVersionsRunbookVersionCollection() {}
    public List<GetRunbookVersionsRunbookVersionCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRunbookVersionsRunbookVersionCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetRunbookVersionsRunbookVersionCollectionItem> items;
        public Builder() {}
        public Builder(GetRunbookVersionsRunbookVersionCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetRunbookVersionsRunbookVersionCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetRunbookVersionsRunbookVersionCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetRunbookVersionsRunbookVersionCollectionItem... items) {
            return items(List.of(items));
        }
        public GetRunbookVersionsRunbookVersionCollection build() {
            final var _resultValue = new GetRunbookVersionsRunbookVersionCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
