// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.MeteringComputation.outputs.GetSchedulesScheduleCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSchedulesScheduleCollection {
    private List<GetSchedulesScheduleCollectionItem> items;

    private GetSchedulesScheduleCollection() {}
    public List<GetSchedulesScheduleCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSchedulesScheduleCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetSchedulesScheduleCollectionItem> items;
        public Builder() {}
        public Builder(GetSchedulesScheduleCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetSchedulesScheduleCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetSchedulesScheduleCollectionItem... items) {
            return items(List.of(items));
        }
        public GetSchedulesScheduleCollection build() {
            final var o = new GetSchedulesScheduleCollection();
            o.items = items;
            return o;
        }
    }
}