// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.VisualBuilder.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.VisualBuilder.outputs.GetVbInstanceApplicationsApplicationSummaryCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetVbInstanceApplicationsApplicationSummaryCollection {
    private List<GetVbInstanceApplicationsApplicationSummaryCollectionItem> items;

    private GetVbInstanceApplicationsApplicationSummaryCollection() {}
    public List<GetVbInstanceApplicationsApplicationSummaryCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVbInstanceApplicationsApplicationSummaryCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetVbInstanceApplicationsApplicationSummaryCollectionItem> items;
        public Builder() {}
        public Builder(GetVbInstanceApplicationsApplicationSummaryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetVbInstanceApplicationsApplicationSummaryCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetVbInstanceApplicationsApplicationSummaryCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetVbInstanceApplicationsApplicationSummaryCollectionItem... items) {
            return items(List.of(items));
        }
        public GetVbInstanceApplicationsApplicationSummaryCollection build() {
            final var _resultValue = new GetVbInstanceApplicationsApplicationSummaryCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
