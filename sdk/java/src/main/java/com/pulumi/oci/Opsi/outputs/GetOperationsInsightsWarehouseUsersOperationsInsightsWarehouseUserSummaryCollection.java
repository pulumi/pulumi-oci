// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Opsi.outputs.GetOperationsInsightsWarehouseUsersOperationsInsightsWarehouseUserSummaryCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetOperationsInsightsWarehouseUsersOperationsInsightsWarehouseUserSummaryCollection {
    private final List<GetOperationsInsightsWarehouseUsersOperationsInsightsWarehouseUserSummaryCollectionItem> items;

    @CustomType.Constructor
    private GetOperationsInsightsWarehouseUsersOperationsInsightsWarehouseUserSummaryCollection(@CustomType.Parameter("items") List<GetOperationsInsightsWarehouseUsersOperationsInsightsWarehouseUserSummaryCollectionItem> items) {
        this.items = items;
    }

    public List<GetOperationsInsightsWarehouseUsersOperationsInsightsWarehouseUserSummaryCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetOperationsInsightsWarehouseUsersOperationsInsightsWarehouseUserSummaryCollection defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetOperationsInsightsWarehouseUsersOperationsInsightsWarehouseUserSummaryCollectionItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(GetOperationsInsightsWarehouseUsersOperationsInsightsWarehouseUserSummaryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(List<GetOperationsInsightsWarehouseUsersOperationsInsightsWarehouseUserSummaryCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetOperationsInsightsWarehouseUsersOperationsInsightsWarehouseUserSummaryCollectionItem... items) {
            return items(List.of(items));
        }        public GetOperationsInsightsWarehouseUsersOperationsInsightsWarehouseUserSummaryCollection build() {
            return new GetOperationsInsightsWarehouseUsersOperationsInsightsWarehouseUserSummaryCollection(items);
        }
    }
}
