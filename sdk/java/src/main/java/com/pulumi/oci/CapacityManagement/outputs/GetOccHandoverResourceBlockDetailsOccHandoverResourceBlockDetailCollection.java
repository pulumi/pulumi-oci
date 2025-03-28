// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CapacityManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CapacityManagement.outputs.GetOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollection {
    /**
     * @return An array of details about an occ handover resource block.
     * 
     */
    private List<GetOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollectionItem> items;

    private GetOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollection() {}
    /**
     * @return An array of details about an occ handover resource block.
     * 
     */
    public List<GetOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollectionItem> items;
        public Builder() {}
        public Builder(GetOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollectionItem... items) {
            return items(List.of(items));
        }
        public GetOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollection build() {
            final var _resultValue = new GetOccHandoverResourceBlockDetailsOccHandoverResourceBlockDetailCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
