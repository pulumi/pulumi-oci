// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiAnomalyDetection.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDetectionDataAssetsDataAssetCollectionItemDataSourceDetailVersionSpecificDetail {
    /**
     * @return Bucket Name for influx connection
     * 
     */
    private String bucket;
    /**
     * @return DB Name for influx connection
     * 
     */
    private String databaseName;
    /**
     * @return Data source type where actually data asset is being stored
     * 
     */
    private String influxVersion;
    /**
     * @return Org name for the influx db
     * 
     */
    private String organizationName;
    /**
     * @return retention policy is how long the bucket would last
     * 
     */
    private String retentionPolicyName;

    private GetDetectionDataAssetsDataAssetCollectionItemDataSourceDetailVersionSpecificDetail() {}
    /**
     * @return Bucket Name for influx connection
     * 
     */
    public String bucket() {
        return this.bucket;
    }
    /**
     * @return DB Name for influx connection
     * 
     */
    public String databaseName() {
        return this.databaseName;
    }
    /**
     * @return Data source type where actually data asset is being stored
     * 
     */
    public String influxVersion() {
        return this.influxVersion;
    }
    /**
     * @return Org name for the influx db
     * 
     */
    public String organizationName() {
        return this.organizationName;
    }
    /**
     * @return retention policy is how long the bucket would last
     * 
     */
    public String retentionPolicyName() {
        return this.retentionPolicyName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDetectionDataAssetsDataAssetCollectionItemDataSourceDetailVersionSpecificDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String bucket;
        private String databaseName;
        private String influxVersion;
        private String organizationName;
        private String retentionPolicyName;
        public Builder() {}
        public Builder(GetDetectionDataAssetsDataAssetCollectionItemDataSourceDetailVersionSpecificDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bucket = defaults.bucket;
    	      this.databaseName = defaults.databaseName;
    	      this.influxVersion = defaults.influxVersion;
    	      this.organizationName = defaults.organizationName;
    	      this.retentionPolicyName = defaults.retentionPolicyName;
        }

        @CustomType.Setter
        public Builder bucket(String bucket) {
            if (bucket == null) {
              throw new MissingRequiredPropertyException("GetDetectionDataAssetsDataAssetCollectionItemDataSourceDetailVersionSpecificDetail", "bucket");
            }
            this.bucket = bucket;
            return this;
        }
        @CustomType.Setter
        public Builder databaseName(String databaseName) {
            if (databaseName == null) {
              throw new MissingRequiredPropertyException("GetDetectionDataAssetsDataAssetCollectionItemDataSourceDetailVersionSpecificDetail", "databaseName");
            }
            this.databaseName = databaseName;
            return this;
        }
        @CustomType.Setter
        public Builder influxVersion(String influxVersion) {
            if (influxVersion == null) {
              throw new MissingRequiredPropertyException("GetDetectionDataAssetsDataAssetCollectionItemDataSourceDetailVersionSpecificDetail", "influxVersion");
            }
            this.influxVersion = influxVersion;
            return this;
        }
        @CustomType.Setter
        public Builder organizationName(String organizationName) {
            if (organizationName == null) {
              throw new MissingRequiredPropertyException("GetDetectionDataAssetsDataAssetCollectionItemDataSourceDetailVersionSpecificDetail", "organizationName");
            }
            this.organizationName = organizationName;
            return this;
        }
        @CustomType.Setter
        public Builder retentionPolicyName(String retentionPolicyName) {
            if (retentionPolicyName == null) {
              throw new MissingRequiredPropertyException("GetDetectionDataAssetsDataAssetCollectionItemDataSourceDetailVersionSpecificDetail", "retentionPolicyName");
            }
            this.retentionPolicyName = retentionPolicyName;
            return this;
        }
        public GetDetectionDataAssetsDataAssetCollectionItemDataSourceDetailVersionSpecificDetail build() {
            final var _resultValue = new GetDetectionDataAssetsDataAssetCollectionItemDataSourceDetailVersionSpecificDetail();
            _resultValue.bucket = bucket;
            _resultValue.databaseName = databaseName;
            _resultValue.influxVersion = influxVersion;
            _resultValue.organizationName = organizationName;
            _resultValue.retentionPolicyName = retentionPolicyName;
            return _resultValue;
        }
    }
}
