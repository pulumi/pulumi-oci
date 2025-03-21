// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceApplicationTaskScheduleMetadataCountStatisticObjectTypeCountList;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetWorkspaceApplicationTaskScheduleMetadataCountStatistic {
    /**
     * @return The array of statistics.
     * 
     */
    private List<GetWorkspaceApplicationTaskScheduleMetadataCountStatisticObjectTypeCountList> objectTypeCountLists;

    private GetWorkspaceApplicationTaskScheduleMetadataCountStatistic() {}
    /**
     * @return The array of statistics.
     * 
     */
    public List<GetWorkspaceApplicationTaskScheduleMetadataCountStatisticObjectTypeCountList> objectTypeCountLists() {
        return this.objectTypeCountLists;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceApplicationTaskScheduleMetadataCountStatistic defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetWorkspaceApplicationTaskScheduleMetadataCountStatisticObjectTypeCountList> objectTypeCountLists;
        public Builder() {}
        public Builder(GetWorkspaceApplicationTaskScheduleMetadataCountStatistic defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.objectTypeCountLists = defaults.objectTypeCountLists;
        }

        @CustomType.Setter
        public Builder objectTypeCountLists(List<GetWorkspaceApplicationTaskScheduleMetadataCountStatisticObjectTypeCountList> objectTypeCountLists) {
            if (objectTypeCountLists == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleMetadataCountStatistic", "objectTypeCountLists");
            }
            this.objectTypeCountLists = objectTypeCountLists;
            return this;
        }
        public Builder objectTypeCountLists(GetWorkspaceApplicationTaskScheduleMetadataCountStatisticObjectTypeCountList... objectTypeCountLists) {
            return objectTypeCountLists(List.of(objectTypeCountLists));
        }
        public GetWorkspaceApplicationTaskScheduleMetadataCountStatistic build() {
            final var _resultValue = new GetWorkspaceApplicationTaskScheduleMetadataCountStatistic();
            _resultValue.objectTypeCountLists = objectTypeCountLists;
            return _resultValue;
        }
    }
}
