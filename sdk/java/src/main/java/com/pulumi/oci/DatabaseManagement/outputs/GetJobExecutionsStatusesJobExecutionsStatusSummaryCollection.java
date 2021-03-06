// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetJobExecutionsStatusesJobExecutionsStatusSummaryCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetJobExecutionsStatusesJobExecutionsStatusSummaryCollection {
    /**
     * @return A list of JobExecutionsSummary objects.
     * 
     */
    private final List<GetJobExecutionsStatusesJobExecutionsStatusSummaryCollectionItem> items;

    @CustomType.Constructor
    private GetJobExecutionsStatusesJobExecutionsStatusSummaryCollection(@CustomType.Parameter("items") List<GetJobExecutionsStatusesJobExecutionsStatusSummaryCollectionItem> items) {
        this.items = items;
    }

    /**
     * @return A list of JobExecutionsSummary objects.
     * 
     */
    public List<GetJobExecutionsStatusesJobExecutionsStatusSummaryCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetJobExecutionsStatusesJobExecutionsStatusSummaryCollection defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetJobExecutionsStatusesJobExecutionsStatusSummaryCollectionItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(GetJobExecutionsStatusesJobExecutionsStatusSummaryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(List<GetJobExecutionsStatusesJobExecutionsStatusSummaryCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetJobExecutionsStatusesJobExecutionsStatusSummaryCollectionItem... items) {
            return items(List.of(items));
        }        public GetJobExecutionsStatusesJobExecutionsStatusSummaryCollection build() {
            return new GetJobExecutionsStatusesJobExecutionsStatusSummaryCollection(items);
        }
    }
}
