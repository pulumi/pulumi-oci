// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Vbs.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Vbs.outputs.GetInstVbsInstancesVbsInstanceSummaryCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetInstVbsInstancesVbsInstanceSummaryCollection {
    private List<GetInstVbsInstancesVbsInstanceSummaryCollectionItem> items;

    private GetInstVbsInstancesVbsInstanceSummaryCollection() {}
    public List<GetInstVbsInstancesVbsInstanceSummaryCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstVbsInstancesVbsInstanceSummaryCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetInstVbsInstancesVbsInstanceSummaryCollectionItem> items;
        public Builder() {}
        public Builder(GetInstVbsInstancesVbsInstanceSummaryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetInstVbsInstancesVbsInstanceSummaryCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetInstVbsInstancesVbsInstanceSummaryCollectionItem... items) {
            return items(List.of(items));
        }
        public GetInstVbsInstancesVbsInstanceSummaryCollection build() {
            final var o = new GetInstVbsInstancesVbsInstanceSummaryCollection();
            o.items = items;
            return o;
        }
    }
}