// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetByoipAllocatedRangesByoipAllocatedRangeCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetByoipAllocatedRangesByoipAllocatedRangeCollection {
    /**
     * @return A list of subranges of a BYOIP CIDR block allocated to an IP pool.
     * 
     */
    private final List<GetByoipAllocatedRangesByoipAllocatedRangeCollectionItem> items;

    @CustomType.Constructor
    private GetByoipAllocatedRangesByoipAllocatedRangeCollection(@CustomType.Parameter("items") List<GetByoipAllocatedRangesByoipAllocatedRangeCollectionItem> items) {
        this.items = items;
    }

    /**
     * @return A list of subranges of a BYOIP CIDR block allocated to an IP pool.
     * 
     */
    public List<GetByoipAllocatedRangesByoipAllocatedRangeCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetByoipAllocatedRangesByoipAllocatedRangeCollection defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetByoipAllocatedRangesByoipAllocatedRangeCollectionItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(GetByoipAllocatedRangesByoipAllocatedRangeCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(List<GetByoipAllocatedRangesByoipAllocatedRangeCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetByoipAllocatedRangesByoipAllocatedRangeCollectionItem... items) {
            return items(List.of(items));
        }        public GetByoipAllocatedRangesByoipAllocatedRangeCollection build() {
            return new GetByoipAllocatedRangesByoipAllocatedRangeCollection(items);
        }
    }
}
