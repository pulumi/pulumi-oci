// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataCountStatisticObjectTypeCountList;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataCountStatistic {
    /**
     * @return The array of statistics.
     * 
     */
    private List<GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataCountStatisticObjectTypeCountList> objectTypeCountLists;

    private GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataCountStatistic() {}
    /**
     * @return The array of statistics.
     * 
     */
    public List<GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataCountStatisticObjectTypeCountList> objectTypeCountLists() {
        return this.objectTypeCountLists;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataCountStatistic defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataCountStatisticObjectTypeCountList> objectTypeCountLists;
        public Builder() {}
        public Builder(GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataCountStatistic defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.objectTypeCountLists = defaults.objectTypeCountLists;
        }

        @CustomType.Setter
        public Builder objectTypeCountLists(List<GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataCountStatisticObjectTypeCountList> objectTypeCountLists) {
            this.objectTypeCountLists = Objects.requireNonNull(objectTypeCountLists);
            return this;
        }
        public Builder objectTypeCountLists(GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataCountStatisticObjectTypeCountList... objectTypeCountLists) {
            return objectTypeCountLists(List.of(objectTypeCountLists));
        }
        public GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataCountStatistic build() {
            final var o = new GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataCountStatistic();
            o.objectTypeCountLists = objectTypeCountLists;
            return o;
        }
    }
}