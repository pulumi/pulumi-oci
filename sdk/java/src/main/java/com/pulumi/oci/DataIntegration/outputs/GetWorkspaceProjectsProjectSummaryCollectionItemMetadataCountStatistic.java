// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceProjectsProjectSummaryCollectionItemMetadataCountStatisticObjectTypeCountList;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetWorkspaceProjectsProjectSummaryCollectionItemMetadataCountStatistic {
    /**
     * @return The array of statistics.
     * 
     */
    private List<GetWorkspaceProjectsProjectSummaryCollectionItemMetadataCountStatisticObjectTypeCountList> objectTypeCountLists;

    private GetWorkspaceProjectsProjectSummaryCollectionItemMetadataCountStatistic() {}
    /**
     * @return The array of statistics.
     * 
     */
    public List<GetWorkspaceProjectsProjectSummaryCollectionItemMetadataCountStatisticObjectTypeCountList> objectTypeCountLists() {
        return this.objectTypeCountLists;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceProjectsProjectSummaryCollectionItemMetadataCountStatistic defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetWorkspaceProjectsProjectSummaryCollectionItemMetadataCountStatisticObjectTypeCountList> objectTypeCountLists;
        public Builder() {}
        public Builder(GetWorkspaceProjectsProjectSummaryCollectionItemMetadataCountStatistic defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.objectTypeCountLists = defaults.objectTypeCountLists;
        }

        @CustomType.Setter
        public Builder objectTypeCountLists(List<GetWorkspaceProjectsProjectSummaryCollectionItemMetadataCountStatisticObjectTypeCountList> objectTypeCountLists) {
            if (objectTypeCountLists == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceProjectsProjectSummaryCollectionItemMetadataCountStatistic", "objectTypeCountLists");
            }
            this.objectTypeCountLists = objectTypeCountLists;
            return this;
        }
        public Builder objectTypeCountLists(GetWorkspaceProjectsProjectSummaryCollectionItemMetadataCountStatisticObjectTypeCountList... objectTypeCountLists) {
            return objectTypeCountLists(List.of(objectTypeCountLists));
        }
        public GetWorkspaceProjectsProjectSummaryCollectionItemMetadataCountStatistic build() {
            final var _resultValue = new GetWorkspaceProjectsProjectSummaryCollectionItemMetadataCountStatistic();
            _resultValue.objectTypeCountLists = objectTypeCountLists;
            return _resultValue;
        }
    }
}
