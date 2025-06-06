// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemScheduleRefMetadataCountStatisticsObjectTypeCountList {
    /**
     * @return The value for the count statistic object.
     * 
     */
    private String objectCount;
    /**
     * @return The type of object for the count statistic object.
     * 
     */
    private String objectType;

    private GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemScheduleRefMetadataCountStatisticsObjectTypeCountList() {}
    /**
     * @return The value for the count statistic object.
     * 
     */
    public String objectCount() {
        return this.objectCount;
    }
    /**
     * @return The type of object for the count statistic object.
     * 
     */
    public String objectType() {
        return this.objectType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemScheduleRefMetadataCountStatisticsObjectTypeCountList defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String objectCount;
        private String objectType;
        public Builder() {}
        public Builder(GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemScheduleRefMetadataCountStatisticsObjectTypeCountList defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.objectCount = defaults.objectCount;
    	      this.objectType = defaults.objectType;
        }

        @CustomType.Setter
        public Builder objectCount(String objectCount) {
            if (objectCount == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemScheduleRefMetadataCountStatisticsObjectTypeCountList", "objectCount");
            }
            this.objectCount = objectCount;
            return this;
        }
        @CustomType.Setter
        public Builder objectType(String objectType) {
            if (objectType == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemScheduleRefMetadataCountStatisticsObjectTypeCountList", "objectType");
            }
            this.objectType = objectType;
            return this;
        }
        public GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemScheduleRefMetadataCountStatisticsObjectTypeCountList build() {
            final var _resultValue = new GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemScheduleRefMetadataCountStatisticsObjectTypeCountList();
            _resultValue.objectCount = objectCount;
            _resultValue.objectType = objectType;
            return _resultValue;
        }
    }
}
