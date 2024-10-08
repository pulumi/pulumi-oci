// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceApplicationMetadataCountStatisticObjectTypeCountList;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetWorkspaceApplicationMetadataCountStatistic {
    /**
     * @return The array of statistics.
     * 
     */
    private List<GetWorkspaceApplicationMetadataCountStatisticObjectTypeCountList> objectTypeCountLists;

    private GetWorkspaceApplicationMetadataCountStatistic() {}
    /**
     * @return The array of statistics.
     * 
     */
    public List<GetWorkspaceApplicationMetadataCountStatisticObjectTypeCountList> objectTypeCountLists() {
        return this.objectTypeCountLists;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceApplicationMetadataCountStatistic defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetWorkspaceApplicationMetadataCountStatisticObjectTypeCountList> objectTypeCountLists;
        public Builder() {}
        public Builder(GetWorkspaceApplicationMetadataCountStatistic defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.objectTypeCountLists = defaults.objectTypeCountLists;
        }

        @CustomType.Setter
        public Builder objectTypeCountLists(List<GetWorkspaceApplicationMetadataCountStatisticObjectTypeCountList> objectTypeCountLists) {
            if (objectTypeCountLists == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationMetadataCountStatistic", "objectTypeCountLists");
            }
            this.objectTypeCountLists = objectTypeCountLists;
            return this;
        }
        public Builder objectTypeCountLists(GetWorkspaceApplicationMetadataCountStatisticObjectTypeCountList... objectTypeCountLists) {
            return objectTypeCountLists(List.of(objectTypeCountLists));
        }
        public GetWorkspaceApplicationMetadataCountStatistic build() {
            final var _resultValue = new GetWorkspaceApplicationMetadataCountStatistic();
            _resultValue.objectTypeCountLists = objectTypeCountLists;
            return _resultValue;
        }
    }
}
