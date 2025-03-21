// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataLabellingService.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDatasetsDatasetCollectionItemDatasetSourceDetail {
    /**
     * @return Bucket name
     * 
     */
    private String bucket;
    /**
     * @return Bucket namespace name
     * 
     */
    private String namespace;
    /**
     * @return A common path prefix shared by the objects that make up the dataset. Except for the CSV file type, records are not generated for the objects whose names exactly match with the prefix.
     * 
     */
    private String prefix;
    /**
     * @return The type of data source. OBJECT_STORAGE - The source details for an object storage bucket.
     * 
     */
    private String sourceType;

    private GetDatasetsDatasetCollectionItemDatasetSourceDetail() {}
    /**
     * @return Bucket name
     * 
     */
    public String bucket() {
        return this.bucket;
    }
    /**
     * @return Bucket namespace name
     * 
     */
    public String namespace() {
        return this.namespace;
    }
    /**
     * @return A common path prefix shared by the objects that make up the dataset. Except for the CSV file type, records are not generated for the objects whose names exactly match with the prefix.
     * 
     */
    public String prefix() {
        return this.prefix;
    }
    /**
     * @return The type of data source. OBJECT_STORAGE - The source details for an object storage bucket.
     * 
     */
    public String sourceType() {
        return this.sourceType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDatasetsDatasetCollectionItemDatasetSourceDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String bucket;
        private String namespace;
        private String prefix;
        private String sourceType;
        public Builder() {}
        public Builder(GetDatasetsDatasetCollectionItemDatasetSourceDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bucket = defaults.bucket;
    	      this.namespace = defaults.namespace;
    	      this.prefix = defaults.prefix;
    	      this.sourceType = defaults.sourceType;
        }

        @CustomType.Setter
        public Builder bucket(String bucket) {
            if (bucket == null) {
              throw new MissingRequiredPropertyException("GetDatasetsDatasetCollectionItemDatasetSourceDetail", "bucket");
            }
            this.bucket = bucket;
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            if (namespace == null) {
              throw new MissingRequiredPropertyException("GetDatasetsDatasetCollectionItemDatasetSourceDetail", "namespace");
            }
            this.namespace = namespace;
            return this;
        }
        @CustomType.Setter
        public Builder prefix(String prefix) {
            if (prefix == null) {
              throw new MissingRequiredPropertyException("GetDatasetsDatasetCollectionItemDatasetSourceDetail", "prefix");
            }
            this.prefix = prefix;
            return this;
        }
        @CustomType.Setter
        public Builder sourceType(String sourceType) {
            if (sourceType == null) {
              throw new MissingRequiredPropertyException("GetDatasetsDatasetCollectionItemDatasetSourceDetail", "sourceType");
            }
            this.sourceType = sourceType;
            return this;
        }
        public GetDatasetsDatasetCollectionItemDatasetSourceDetail build() {
            final var _resultValue = new GetDatasetsDatasetCollectionItemDatasetSourceDetail();
            _resultValue.bucket = bucket;
            _resultValue.namespace = namespace;
            _resultValue.prefix = prefix;
            _resultValue.sourceType = sourceType;
            return _resultValue;
        }
    }
}
