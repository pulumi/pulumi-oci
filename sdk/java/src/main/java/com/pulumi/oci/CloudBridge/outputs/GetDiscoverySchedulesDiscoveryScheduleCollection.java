// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudBridge.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudBridge.outputs.GetDiscoverySchedulesDiscoveryScheduleCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDiscoverySchedulesDiscoveryScheduleCollection {
    private List<GetDiscoverySchedulesDiscoveryScheduleCollectionItem> items;

    private GetDiscoverySchedulesDiscoveryScheduleCollection() {}
    public List<GetDiscoverySchedulesDiscoveryScheduleCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDiscoverySchedulesDiscoveryScheduleCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDiscoverySchedulesDiscoveryScheduleCollectionItem> items;
        public Builder() {}
        public Builder(GetDiscoverySchedulesDiscoveryScheduleCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetDiscoverySchedulesDiscoveryScheduleCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetDiscoverySchedulesDiscoveryScheduleCollectionItem... items) {
            return items(List.of(items));
        }
        public GetDiscoverySchedulesDiscoveryScheduleCollection build() {
            final var o = new GetDiscoverySchedulesDiscoveryScheduleCollection();
            o.items = items;
            return o;
        }
    }
}