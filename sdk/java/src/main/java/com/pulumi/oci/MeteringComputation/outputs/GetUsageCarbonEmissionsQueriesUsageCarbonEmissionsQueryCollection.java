// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.MeteringComputation.outputs.GetUsageCarbonEmissionsQueriesUsageCarbonEmissionsQueryCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetUsageCarbonEmissionsQueriesUsageCarbonEmissionsQueryCollection {
    private List<GetUsageCarbonEmissionsQueriesUsageCarbonEmissionsQueryCollectionItem> items;

    private GetUsageCarbonEmissionsQueriesUsageCarbonEmissionsQueryCollection() {}
    public List<GetUsageCarbonEmissionsQueriesUsageCarbonEmissionsQueryCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetUsageCarbonEmissionsQueriesUsageCarbonEmissionsQueryCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetUsageCarbonEmissionsQueriesUsageCarbonEmissionsQueryCollectionItem> items;
        public Builder() {}
        public Builder(GetUsageCarbonEmissionsQueriesUsageCarbonEmissionsQueryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetUsageCarbonEmissionsQueriesUsageCarbonEmissionsQueryCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetUsageCarbonEmissionsQueriesUsageCarbonEmissionsQueryCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetUsageCarbonEmissionsQueriesUsageCarbonEmissionsQueryCollectionItem... items) {
            return items(List.of(items));
        }
        public GetUsageCarbonEmissionsQueriesUsageCarbonEmissionsQueryCollection build() {
            final var _resultValue = new GetUsageCarbonEmissionsQueriesUsageCarbonEmissionsQueryCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
