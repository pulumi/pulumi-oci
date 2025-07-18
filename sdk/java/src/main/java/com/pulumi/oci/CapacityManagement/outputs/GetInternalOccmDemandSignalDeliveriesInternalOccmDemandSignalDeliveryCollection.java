// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CapacityManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CapacityManagement.outputs.GetInternalOccmDemandSignalDeliveriesInternalOccmDemandSignalDeliveryCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetInternalOccmDemandSignalDeliveriesInternalOccmDemandSignalDeliveryCollection {
    private List<GetInternalOccmDemandSignalDeliveriesInternalOccmDemandSignalDeliveryCollectionItem> items;

    private GetInternalOccmDemandSignalDeliveriesInternalOccmDemandSignalDeliveryCollection() {}
    public List<GetInternalOccmDemandSignalDeliveriesInternalOccmDemandSignalDeliveryCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInternalOccmDemandSignalDeliveriesInternalOccmDemandSignalDeliveryCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetInternalOccmDemandSignalDeliveriesInternalOccmDemandSignalDeliveryCollectionItem> items;
        public Builder() {}
        public Builder(GetInternalOccmDemandSignalDeliveriesInternalOccmDemandSignalDeliveryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetInternalOccmDemandSignalDeliveriesInternalOccmDemandSignalDeliveryCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetInternalOccmDemandSignalDeliveriesInternalOccmDemandSignalDeliveryCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetInternalOccmDemandSignalDeliveriesInternalOccmDemandSignalDeliveryCollectionItem... items) {
            return items(List.of(items));
        }
        public GetInternalOccmDemandSignalDeliveriesInternalOccmDemandSignalDeliveryCollection build() {
            final var _resultValue = new GetInternalOccmDemandSignalDeliveriesInternalOccmDemandSignalDeliveryCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
