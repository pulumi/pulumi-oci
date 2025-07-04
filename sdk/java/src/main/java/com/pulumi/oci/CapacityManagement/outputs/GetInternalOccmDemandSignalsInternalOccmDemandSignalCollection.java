// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CapacityManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CapacityManagement.outputs.GetInternalOccmDemandSignalsInternalOccmDemandSignalCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetInternalOccmDemandSignalsInternalOccmDemandSignalCollection {
    private List<GetInternalOccmDemandSignalsInternalOccmDemandSignalCollectionItem> items;

    private GetInternalOccmDemandSignalsInternalOccmDemandSignalCollection() {}
    public List<GetInternalOccmDemandSignalsInternalOccmDemandSignalCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInternalOccmDemandSignalsInternalOccmDemandSignalCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetInternalOccmDemandSignalsInternalOccmDemandSignalCollectionItem> items;
        public Builder() {}
        public Builder(GetInternalOccmDemandSignalsInternalOccmDemandSignalCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetInternalOccmDemandSignalsInternalOccmDemandSignalCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetInternalOccmDemandSignalsInternalOccmDemandSignalCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetInternalOccmDemandSignalsInternalOccmDemandSignalCollectionItem... items) {
            return items(List.of(items));
        }
        public GetInternalOccmDemandSignalsInternalOccmDemandSignalCollection build() {
            final var _resultValue = new GetInternalOccmDemandSignalsInternalOccmDemandSignalCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
