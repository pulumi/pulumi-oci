// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiLanguage.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.AiLanguage.outputs.GetModelTrainingDatasetLocationDetail;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetModelTrainingDataset {
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
    private List<GetModelTrainingDatasetLocationDetail> locationDetails;

    private GetModelTrainingDataset() {}
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
    public List<GetModelTrainingDatasetLocationDetail> locationDetails() {
        return this.locationDetails;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetModelTrainingDataset defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String datasetId;
        private String datasetType;
        private List<GetModelTrainingDatasetLocationDetail> locationDetails;
        public Builder() {}
        public Builder(GetModelTrainingDataset defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.datasetId = defaults.datasetId;
    	      this.datasetType = defaults.datasetType;
    	      this.locationDetails = defaults.locationDetails;
        }

        @CustomType.Setter
        public Builder datasetId(String datasetId) {
            if (datasetId == null) {
              throw new MissingRequiredPropertyException("GetModelTrainingDataset", "datasetId");
            }
            this.datasetId = datasetId;
            return this;
        }
        @CustomType.Setter
        public Builder datasetType(String datasetType) {
            if (datasetType == null) {
              throw new MissingRequiredPropertyException("GetModelTrainingDataset", "datasetType");
            }
            this.datasetType = datasetType;
            return this;
        }
        @CustomType.Setter
        public Builder locationDetails(List<GetModelTrainingDatasetLocationDetail> locationDetails) {
            if (locationDetails == null) {
              throw new MissingRequiredPropertyException("GetModelTrainingDataset", "locationDetails");
            }
            this.locationDetails = locationDetails;
            return this;
        }
        public Builder locationDetails(GetModelTrainingDatasetLocationDetail... locationDetails) {
            return locationDetails(List.of(locationDetails));
        }
        public GetModelTrainingDataset build() {
            final var _resultValue = new GetModelTrainingDataset();
            _resultValue.datasetId = datasetId;
            _resultValue.datasetType = datasetType;
            _resultValue.locationDetails = locationDetails;
            return _resultValue;
        }
    }
}
