// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Opsi.outputs.GetExadataInsightsExadataInsightSummaryCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetExadataInsightsExadataInsightSummaryCollection {
    private List<GetExadataInsightsExadataInsightSummaryCollectionItem> items;

    private GetExadataInsightsExadataInsightSummaryCollection() {}
    public List<GetExadataInsightsExadataInsightSummaryCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExadataInsightsExadataInsightSummaryCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetExadataInsightsExadataInsightSummaryCollectionItem> items;
        public Builder() {}
        public Builder(GetExadataInsightsExadataInsightSummaryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetExadataInsightsExadataInsightSummaryCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetExadataInsightsExadataInsightSummaryCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetExadataInsightsExadataInsightSummaryCollectionItem... items) {
            return items(List.of(items));
        }
        public GetExadataInsightsExadataInsightSummaryCollection build() {
            final var _resultValue = new GetExadataInsightsExadataInsightSummaryCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
