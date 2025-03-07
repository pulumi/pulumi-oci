// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiLanguage.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.AiLanguage.outputs.GetModelTestStrategyTestingDatasetLocationDetail;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetModelTestStrategyTestingDataset {
    /**
     * @return Data Science Labelling Service OCID
     * 
     */
    private String datasetId;
    /**
     * @return Possible data sets
     * 
     */
    private String datasetType;
    /**
     * @return Possible object storage location types
     * 
     */
    private List<GetModelTestStrategyTestingDatasetLocationDetail> locationDetails;

    private GetModelTestStrategyTestingDataset() {}
    /**
     * @return Data Science Labelling Service OCID
     * 
     */
    public String datasetId() {
        return this.datasetId;
    }
    /**
     * @return Possible data sets
     * 
     */
    public String datasetType() {
        return this.datasetType;
    }
    /**
     * @return Possible object storage location types
     * 
     */
    public List<GetModelTestStrategyTestingDatasetLocationDetail> locationDetails() {
        return this.locationDetails;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetModelTestStrategyTestingDataset defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String datasetId;
        private String datasetType;
        private List<GetModelTestStrategyTestingDatasetLocationDetail> locationDetails;
        public Builder() {}
        public Builder(GetModelTestStrategyTestingDataset defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.datasetId = defaults.datasetId;
    	      this.datasetType = defaults.datasetType;
    	      this.locationDetails = defaults.locationDetails;
        }

        @CustomType.Setter
        public Builder datasetId(String datasetId) {
            if (datasetId == null) {
              throw new MissingRequiredPropertyException("GetModelTestStrategyTestingDataset", "datasetId");
            }
            this.datasetId = datasetId;
            return this;
        }
        @CustomType.Setter
        public Builder datasetType(String datasetType) {
            if (datasetType == null) {
              throw new MissingRequiredPropertyException("GetModelTestStrategyTestingDataset", "datasetType");
            }
            this.datasetType = datasetType;
            return this;
        }
        @CustomType.Setter
        public Builder locationDetails(List<GetModelTestStrategyTestingDatasetLocationDetail> locationDetails) {
            if (locationDetails == null) {
              throw new MissingRequiredPropertyException("GetModelTestStrategyTestingDataset", "locationDetails");
            }
            this.locationDetails = locationDetails;
            return this;
        }
        public Builder locationDetails(GetModelTestStrategyTestingDatasetLocationDetail... locationDetails) {
            return locationDetails(List.of(locationDetails));
        }
        public GetModelTestStrategyTestingDataset build() {
            final var _resultValue = new GetModelTestStrategyTestingDataset();
            _resultValue.datasetId = datasetId;
            _resultValue.datasetType = datasetType;
            _resultValue.locationDetails = locationDetails;
            return _resultValue;
        }
    }
}
