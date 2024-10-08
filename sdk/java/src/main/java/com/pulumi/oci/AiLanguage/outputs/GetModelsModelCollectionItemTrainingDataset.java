// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiLanguage.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.AiLanguage.outputs.GetModelsModelCollectionItemTrainingDatasetLocationDetail;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetModelsModelCollectionItemTrainingDataset {
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
    private List<GetModelsModelCollectionItemTrainingDatasetLocationDetail> locationDetails;

    private GetModelsModelCollectionItemTrainingDataset() {}
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
    public List<GetModelsModelCollectionItemTrainingDatasetLocationDetail> locationDetails() {
        return this.locationDetails;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetModelsModelCollectionItemTrainingDataset defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String datasetId;
        private String datasetType;
        private List<GetModelsModelCollectionItemTrainingDatasetLocationDetail> locationDetails;
        public Builder() {}
        public Builder(GetModelsModelCollectionItemTrainingDataset defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.datasetId = defaults.datasetId;
    	      this.datasetType = defaults.datasetType;
    	      this.locationDetails = defaults.locationDetails;
        }

        @CustomType.Setter
        public Builder datasetId(String datasetId) {
            if (datasetId == null) {
              throw new MissingRequiredPropertyException("GetModelsModelCollectionItemTrainingDataset", "datasetId");
            }
            this.datasetId = datasetId;
            return this;
        }
        @CustomType.Setter
        public Builder datasetType(String datasetType) {
            if (datasetType == null) {
              throw new MissingRequiredPropertyException("GetModelsModelCollectionItemTrainingDataset", "datasetType");
            }
            this.datasetType = datasetType;
            return this;
        }
        @CustomType.Setter
        public Builder locationDetails(List<GetModelsModelCollectionItemTrainingDatasetLocationDetail> locationDetails) {
            if (locationDetails == null) {
              throw new MissingRequiredPropertyException("GetModelsModelCollectionItemTrainingDataset", "locationDetails");
            }
            this.locationDetails = locationDetails;
            return this;
        }
        public Builder locationDetails(GetModelsModelCollectionItemTrainingDatasetLocationDetail... locationDetails) {
            return locationDetails(List.of(locationDetails));
        }
        public GetModelsModelCollectionItemTrainingDataset build() {
            final var _resultValue = new GetModelsModelCollectionItemTrainingDataset();
            _resultValue.datasetId = datasetId;
            _resultValue.datasetType = datasetType;
            _resultValue.locationDetails = locationDetails;
            return _resultValue;
        }
    }
}
