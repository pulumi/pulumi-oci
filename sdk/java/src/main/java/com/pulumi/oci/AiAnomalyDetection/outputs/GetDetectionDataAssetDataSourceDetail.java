// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiAnomalyDetection.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.AiAnomalyDetection.outputs.GetDetectionDataAssetDataSourceDetailVersionSpecificDetail;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDetectionDataAssetDataSourceDetail {
    /**
     * @return atp db password Secret Id
     * 
     */
    private String atpPasswordSecretId;
    /**
     * @return atp db user name
     * 
     */
    private String atpUserName;
    /**
     * @return Bucket Name for influx connection
     * 
     */
    private String bucket;
    /**
     * @return OCID of the secret containing the containers certificates of ATP wallet
     * 
     */
    private String cwalletFileSecretId;
    /**
     * @return Data source type where actually data asset is being stored
     * 
     */
    private String dataSourceType;
    /**
     * @return DB Name for influx connection
     * 
     */
    private String databaseName;
    /**
     * @return OCID of the secret containing the PDB&#39;S certificates of ATP wallet
     * 
     */
    private String ewalletFileSecretId;
    /**
     * @return OCID of the secret containing Keystore.jks file of the ATP wallet
     * 
     */
    private String keyStoreFileSecretId;
    /**
     * @return Measurement name for influx
     * 
     */
    private String measurementName;
    /**
     * @return Object storage namespace
     * 
     */
    private String namespace;
    /**
     * @return File name
     * 
     */
    private String object;
    /**
     * @return OCID of the secret that contains jdbc properties file of ATP wallet
     * 
     */
    private String ojdbcFileSecretId;
    /**
     * @return Password Secret Id for the influx connection
     * 
     */
    private String passwordSecretId;
    /**
     * @return atp database table name
     * 
     */
    private String tableName;
    /**
     * @return OCID of the secret that contains the tnsnames file of ATP wallet
     * 
     */
    private String tnsnamesFileSecretId;
    /**
     * @return OCID of the secret containing truststore.jks file of the ATP wallet
     * 
     */
    private String truststoreFileSecretId;
    /**
     * @return public IP address and port to influx DB
     * 
     */
    private String url;
    /**
     * @return Username for connection to Influx
     * 
     */
    private String userName;
    /**
     * @return Possible data sources
     * 
     */
    private List<GetDetectionDataAssetDataSourceDetailVersionSpecificDetail> versionSpecificDetails;
    /**
     * @return wallet password Secret ID in String format
     * 
     */
    private String walletPasswordSecretId;

    private GetDetectionDataAssetDataSourceDetail() {}
    /**
     * @return atp db password Secret Id
     * 
     */
    public String atpPasswordSecretId() {
        return this.atpPasswordSecretId;
    }
    /**
     * @return atp db user name
     * 
     */
    public String atpUserName() {
        return this.atpUserName;
    }
    /**
     * @return Bucket Name for influx connection
     * 
     */
    public String bucket() {
        return this.bucket;
    }
    /**
     * @return OCID of the secret containing the containers certificates of ATP wallet
     * 
     */
    public String cwalletFileSecretId() {
        return this.cwalletFileSecretId;
    }
    /**
     * @return Data source type where actually data asset is being stored
     * 
     */
    public String dataSourceType() {
        return this.dataSourceType;
    }
    /**
     * @return DB Name for influx connection
     * 
     */
    public String databaseName() {
        return this.databaseName;
    }
    /**
     * @return OCID of the secret containing the PDB&#39;S certificates of ATP wallet
     * 
     */
    public String ewalletFileSecretId() {
        return this.ewalletFileSecretId;
    }
    /**
     * @return OCID of the secret containing Keystore.jks file of the ATP wallet
     * 
     */
    public String keyStoreFileSecretId() {
        return this.keyStoreFileSecretId;
    }
    /**
     * @return Measurement name for influx
     * 
     */
    public String measurementName() {
        return this.measurementName;
    }
    /**
     * @return Object storage namespace
     * 
     */
    public String namespace() {
        return this.namespace;
    }
    /**
     * @return File name
     * 
     */
    public String object() {
        return this.object;
    }
    /**
     * @return OCID of the secret that contains jdbc properties file of ATP wallet
     * 
     */
    public String ojdbcFileSecretId() {
        return this.ojdbcFileSecretId;
    }
    /**
     * @return Password Secret Id for the influx connection
     * 
     */
    public String passwordSecretId() {
        return this.passwordSecretId;
    }
    /**
     * @return atp database table name
     * 
     */
    public String tableName() {
        return this.tableName;
    }
    /**
     * @return OCID of the secret that contains the tnsnames file of ATP wallet
     * 
     */
    public String tnsnamesFileSecretId() {
        return this.tnsnamesFileSecretId;
    }
    /**
     * @return OCID of the secret containing truststore.jks file of the ATP wallet
     * 
     */
    public String truststoreFileSecretId() {
        return this.truststoreFileSecretId;
    }
    /**
     * @return public IP address and port to influx DB
     * 
     */
    public String url() {
        return this.url;
    }
    /**
     * @return Username for connection to Influx
     * 
     */
    public String userName() {
        return this.userName;
    }
    /**
     * @return Possible data sources
     * 
     */
    public List<GetDetectionDataAssetDataSourceDetailVersionSpecificDetail> versionSpecificDetails() {
        return this.versionSpecificDetails;
    }
    /**
     * @return wallet password Secret ID in String format
     * 
     */
    public String walletPasswordSecretId() {
        return this.walletPasswordSecretId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDetectionDataAssetDataSourceDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String atpPasswordSecretId;
        private String atpUserName;
        private String bucket;
        private String cwalletFileSecretId;
        private String dataSourceType;
        private String databaseName;
        private String ewalletFileSecretId;
        private String keyStoreFileSecretId;
        private String measurementName;
        private String namespace;
        private String object;
        private String ojdbcFileSecretId;
        private String passwordSecretId;
        private String tableName;
        private String tnsnamesFileSecretId;
        private String truststoreFileSecretId;
        private String url;
        private String userName;
        private List<GetDetectionDataAssetDataSourceDetailVersionSpecificDetail> versionSpecificDetails;
        private String walletPasswordSecretId;
        public Builder() {}
        public Builder(GetDetectionDataAssetDataSourceDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.atpPasswordSecretId = defaults.atpPasswordSecretId;
    	      this.atpUserName = defaults.atpUserName;
    	      this.bucket = defaults.bucket;
    	      this.cwalletFileSecretId = defaults.cwalletFileSecretId;
    	      this.dataSourceType = defaults.dataSourceType;
    	      this.databaseName = defaults.databaseName;
    	      this.ewalletFileSecretId = defaults.ewalletFileSecretId;
    	      this.keyStoreFileSecretId = defaults.keyStoreFileSecretId;
    	      this.measurementName = defaults.measurementName;
    	      this.namespace = defaults.namespace;
    	      this.object = defaults.object;
    	      this.ojdbcFileSecretId = defaults.ojdbcFileSecretId;
    	      this.passwordSecretId = defaults.passwordSecretId;
    	      this.tableName = defaults.tableName;
    	      this.tnsnamesFileSecretId = defaults.tnsnamesFileSecretId;
    	      this.truststoreFileSecretId = defaults.truststoreFileSecretId;
    	      this.url = defaults.url;
    	      this.userName = defaults.userName;
    	      this.versionSpecificDetails = defaults.versionSpecificDetails;
    	      this.walletPasswordSecretId = defaults.walletPasswordSecretId;
        }

        @CustomType.Setter
        public Builder atpPasswordSecretId(String atpPasswordSecretId) {
            this.atpPasswordSecretId = Objects.requireNonNull(atpPasswordSecretId);
            return this;
        }
        @CustomType.Setter
        public Builder atpUserName(String atpUserName) {
            this.atpUserName = Objects.requireNonNull(atpUserName);
            return this;
        }
        @CustomType.Setter
        public Builder bucket(String bucket) {
            this.bucket = Objects.requireNonNull(bucket);
            return this;
        }
        @CustomType.Setter
        public Builder cwalletFileSecretId(String cwalletFileSecretId) {
            this.cwalletFileSecretId = Objects.requireNonNull(cwalletFileSecretId);
            return this;
        }
        @CustomType.Setter
        public Builder dataSourceType(String dataSourceType) {
            this.dataSourceType = Objects.requireNonNull(dataSourceType);
            return this;
        }
        @CustomType.Setter
        public Builder databaseName(String databaseName) {
            this.databaseName = Objects.requireNonNull(databaseName);
            return this;
        }
        @CustomType.Setter
        public Builder ewalletFileSecretId(String ewalletFileSecretId) {
            this.ewalletFileSecretId = Objects.requireNonNull(ewalletFileSecretId);
            return this;
        }
        @CustomType.Setter
        public Builder keyStoreFileSecretId(String keyStoreFileSecretId) {
            this.keyStoreFileSecretId = Objects.requireNonNull(keyStoreFileSecretId);
            return this;
        }
        @CustomType.Setter
        public Builder measurementName(String measurementName) {
            this.measurementName = Objects.requireNonNull(measurementName);
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            this.namespace = Objects.requireNonNull(namespace);
            return this;
        }
        @CustomType.Setter
        public Builder object(String object) {
            this.object = Objects.requireNonNull(object);
            return this;
        }
        @CustomType.Setter
        public Builder ojdbcFileSecretId(String ojdbcFileSecretId) {
            this.ojdbcFileSecretId = Objects.requireNonNull(ojdbcFileSecretId);
            return this;
        }
        @CustomType.Setter
        public Builder passwordSecretId(String passwordSecretId) {
            this.passwordSecretId = Objects.requireNonNull(passwordSecretId);
            return this;
        }
        @CustomType.Setter
        public Builder tableName(String tableName) {
            this.tableName = Objects.requireNonNull(tableName);
            return this;
        }
        @CustomType.Setter
        public Builder tnsnamesFileSecretId(String tnsnamesFileSecretId) {
            this.tnsnamesFileSecretId = Objects.requireNonNull(tnsnamesFileSecretId);
            return this;
        }
        @CustomType.Setter
        public Builder truststoreFileSecretId(String truststoreFileSecretId) {
            this.truststoreFileSecretId = Objects.requireNonNull(truststoreFileSecretId);
            return this;
        }
        @CustomType.Setter
        public Builder url(String url) {
            this.url = Objects.requireNonNull(url);
            return this;
        }
        @CustomType.Setter
        public Builder userName(String userName) {
            this.userName = Objects.requireNonNull(userName);
            return this;
        }
        @CustomType.Setter
        public Builder versionSpecificDetails(List<GetDetectionDataAssetDataSourceDetailVersionSpecificDetail> versionSpecificDetails) {
            this.versionSpecificDetails = Objects.requireNonNull(versionSpecificDetails);
            return this;
        }
        public Builder versionSpecificDetails(GetDetectionDataAssetDataSourceDetailVersionSpecificDetail... versionSpecificDetails) {
            return versionSpecificDetails(List.of(versionSpecificDetails));
        }
        @CustomType.Setter
        public Builder walletPasswordSecretId(String walletPasswordSecretId) {
            this.walletPasswordSecretId = Objects.requireNonNull(walletPasswordSecretId);
            return this;
        }
        public GetDetectionDataAssetDataSourceDetail build() {
            final var o = new GetDetectionDataAssetDataSourceDetail();
            o.atpPasswordSecretId = atpPasswordSecretId;
            o.atpUserName = atpUserName;
            o.bucket = bucket;
            o.cwalletFileSecretId = cwalletFileSecretId;
            o.dataSourceType = dataSourceType;
            o.databaseName = databaseName;
            o.ewalletFileSecretId = ewalletFileSecretId;
            o.keyStoreFileSecretId = keyStoreFileSecretId;
            o.measurementName = measurementName;
            o.namespace = namespace;
            o.object = object;
            o.ojdbcFileSecretId = ojdbcFileSecretId;
            o.passwordSecretId = passwordSecretId;
            o.tableName = tableName;
            o.tnsnamesFileSecretId = tnsnamesFileSecretId;
            o.truststoreFileSecretId = truststoreFileSecretId;
            o.url = url;
            o.userName = userName;
            o.versionSpecificDetails = versionSpecificDetails;
            o.walletPasswordSecretId = walletPasswordSecretId;
            return o;
        }
    }
}