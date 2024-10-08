// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CapacityManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CapacityManagement.outputs.GetInternalOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetInternalOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollection {
    /**
     * @return An array of details about an occ handover resource block.
     * 
     */
    private List<GetInternalOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollectionItem> items;

    private GetInternalOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollection() {}
    /**
     * @return An array of details about an occ handover resource block.
     * 
     */
    public List<GetInternalOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInternalOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetInternalOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollectionItem> items;
        public Builder() {}
        public Builder(GetInternalOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetInternalOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetInternalOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetInternalOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollectionItem... items) {
            return items(List.of(items));
        }
        public GetInternalOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollection build() {
            final var _resultValue = new GetInternalOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
