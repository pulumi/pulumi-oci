// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.VisualBuilder.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.VisualBuilder.outputs.GetVbInstancesVbInstanceSummaryCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetVbInstancesVbInstanceSummaryCollection {
    private List<GetVbInstancesVbInstanceSummaryCollectionItem> items;

    private GetVbInstancesVbInstanceSummaryCollection() {}
    public List<GetVbInstancesVbInstanceSummaryCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVbInstancesVbInstanceSummaryCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetVbInstancesVbInstanceSummaryCollectionItem> items;
        public Builder() {}
        public Builder(GetVbInstancesVbInstanceSummaryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetVbInstancesVbInstanceSummaryCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetVbInstancesVbInstanceSummaryCollectionItem... items) {
            return items(List.of(items));
        }
        public GetVbInstancesVbInstanceSummaryCollection build() {
            final var o = new GetVbInstancesVbInstanceSummaryCollection();
            o.items = items;
            return o;
        }
    }
}