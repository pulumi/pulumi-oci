// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabaseOptimizerStatisticsCollectionAggregationsOptimizerStatisticsCollectionAggregationsCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetManagedDatabaseOptimizerStatisticsCollectionAggregationsOptimizerStatisticsCollectionAggregationsCollection {
    /**
     * @return The list of Optimizer Statistics Collection details.
     * 
     */
    private List<GetManagedDatabaseOptimizerStatisticsCollectionAggregationsOptimizerStatisticsCollectionAggregationsCollectionItem> items;

    private GetManagedDatabaseOptimizerStatisticsCollectionAggregationsOptimizerStatisticsCollectionAggregationsCollection() {}
    /**
     * @return The list of Optimizer Statistics Collection details.
     * 
     */
    public List<GetManagedDatabaseOptimizerStatisticsCollectionAggregationsOptimizerStatisticsCollectionAggregationsCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabaseOptimizerStatisticsCollectionAggregationsOptimizerStatisticsCollectionAggregationsCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetManagedDatabaseOptimizerStatisticsCollectionAggregationsOptimizerStatisticsCollectionAggregationsCollectionItem> items;
        public Builder() {}
        public Builder(GetManagedDatabaseOptimizerStatisticsCollectionAggregationsOptimizerStatisticsCollectionAggregationsCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetManagedDatabaseOptimizerStatisticsCollectionAggregationsOptimizerStatisticsCollectionAggregationsCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetManagedDatabaseOptimizerStatisticsCollectionAggregationsOptimizerStatisticsCollectionAggregationsCollectionItem... items) {
            return items(List.of(items));
        }
        public GetManagedDatabaseOptimizerStatisticsCollectionAggregationsOptimizerStatisticsCollectionAggregationsCollection build() {
            final var o = new GetManagedDatabaseOptimizerStatisticsCollectionAggregationsOptimizerStatisticsCollectionAggregationsCollection();
            o.items = items;
            return o;
        }
    }
}