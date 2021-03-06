// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiVision.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetModelsModelCollectionItemTrainingDataset {
    /**
     * @return The name of the ObjectStorage bucket that contains the input data file.
     * 
     */
    private final String bucket;
    /**
     * @return The OCID of the Data Science Labeling Dataset.
     * 
     */
    private final String datasetId;
    /**
     * @return Type of the Dataset.
     * 
     */
    private final String datasetType;
    private final String namespaceName;
    /**
     * @return The object name of the input data file.
     * 
     */
    private final String object;

    @CustomType.Constructor
    private GetModelsModelCollectionItemTrainingDataset(
        @CustomType.Parameter("bucket") String bucket,
        @CustomType.Parameter("datasetId") String datasetId,
        @CustomType.Parameter("datasetType") String datasetType,
        @CustomType.Parameter("namespaceName") String namespaceName,
        @CustomType.Parameter("object") String object) {
        this.bucket = bucket;
        this.datasetId = datasetId;
        this.datasetType = datasetType;
        this.namespaceName = namespaceName;
        this.object = object;
    }

    /**
     * @return The name of the ObjectStorage bucket that contains the input data file.
     * 
     */
    public String bucket() {
        return this.bucket;
    }
    /**
     * @return The OCID of the Data Science Labeling Dataset.
     * 
     */
    public String datasetId() {
        return this.datasetId;
    }
    /**
     * @return Type of the Dataset.
     * 
     */
    public String datasetType() {
        return this.datasetType;
    }
    public String namespaceName() {
        return this.namespaceName;
    }
    /**
     * @return The object name of the input data file.
     * 
     */
    public String object() {
        return this.object;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetModelsModelCollectionItemTrainingDataset defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String bucket;
        private String datasetId;
        private String datasetType;
        private String namespaceName;
        private String object;

        public Builder() {
    	      // Empty
        }

        public Builder(GetModelsModelCollectionItemTrainingDataset defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bucket = defaults.bucket;
    	      this.datasetId = defaults.datasetId;
    	      this.datasetType = defaults.datasetType;
    	      this.namespaceName = defaults.namespaceName;
    	      this.object = defaults.object;
        }

        public Builder bucket(String bucket) {
            this.bucket = Objects.requireNonNull(bucket);
            return this;
        }
        public Builder datasetId(String datasetId) {
            this.datasetId = Objects.requireNonNull(datasetId);
            return this;
        }
        public Builder datasetType(String datasetType) {
            this.datasetType = Objects.requireNonNull(datasetType);
            return this;
        }
        public Builder namespaceName(String namespaceName) {
            this.namespaceName = Objects.requireNonNull(namespaceName);
            return this;
        }
        public Builder object(String object) {
            this.object = Objects.requireNonNull(object);
            return this;
        }        public GetModelsModelCollectionItemTrainingDataset build() {
            return new GetModelsModelCollectionItemTrainingDataset(bucket, datasetId, datasetType, namespaceName, object);
        }
    }
}
