// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiAnomalyDetection.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.AiAnomalyDetection.inputs.DataAssetDataSourceDetailsVersionSpecificDetailsArgs;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DataAssetDataSourceDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final DataAssetDataSourceDetailsArgs Empty = new DataAssetDataSourceDetailsArgs();

    /**
     * atp db password Secret Id
     * 
     */
    @Import(name="atpPasswordSecretId")
    private @Nullable Output<String> atpPasswordSecretId;

    /**
     * @return atp db password Secret Id
     * 
     */
    public Optional<Output<String>> atpPasswordSecretId() {
        return Optional.ofNullable(this.atpPasswordSecretId);
    }

    /**
     * atp db user name
     * 
     */
    @Import(name="atpUserName")
    private @Nullable Output<String> atpUserName;

    /**
     * @return atp db user name
     * 
     */
    public Optional<Output<String>> atpUserName() {
        return Optional.ofNullable(this.atpUserName);
    }

    /**
     * Object storage bucket name
     * 
     */
    @Import(name="bucket")
    private @Nullable Output<String> bucket;

    /**
     * @return Object storage bucket name
     * 
     */
    public Optional<Output<String>> bucket() {
        return Optional.ofNullable(this.bucket);
    }

    /**
     * OCID of the secret containing the containers certificates of ATP wallet
     * 
     */
    @Import(name="cwalletFileSecretId")
    private @Nullable Output<String> cwalletFileSecretId;

    /**
     * @return OCID of the secret containing the containers certificates of ATP wallet
     * 
     */
    public Optional<Output<String>> cwalletFileSecretId() {
        return Optional.ofNullable(this.cwalletFileSecretId);
    }

    /**
     * Data source type where actually data asset is being stored
     * 
     */
    @Import(name="dataSourceType", required=true)
    private Output<String> dataSourceType;

    /**
     * @return Data source type where actually data asset is being stored
     * 
     */
    public Output<String> dataSourceType() {
        return this.dataSourceType;
    }

    /**
     * atp database name
     * 
     */
    @Import(name="databaseName")
    private @Nullable Output<String> databaseName;

    /**
     * @return atp database name
     * 
     */
    public Optional<Output<String>> databaseName() {
        return Optional.ofNullable(this.databaseName);
    }

    /**
     * OCID of the secret containing the PDB&#39;S certificates of ATP wallet
     * 
     */
    @Import(name="ewalletFileSecretId")
    private @Nullable Output<String> ewalletFileSecretId;

    /**
     * @return OCID of the secret containing the PDB&#39;S certificates of ATP wallet
     * 
     */
    public Optional<Output<String>> ewalletFileSecretId() {
        return Optional.ofNullable(this.ewalletFileSecretId);
    }

    /**
     * OCID of the secret containing Keystore.jks file of the ATP wallet
     * 
     */
    @Import(name="keyStoreFileSecretId")
    private @Nullable Output<String> keyStoreFileSecretId;

    /**
     * @return OCID of the secret containing Keystore.jks file of the ATP wallet
     * 
     */
    public Optional<Output<String>> keyStoreFileSecretId() {
        return Optional.ofNullable(this.keyStoreFileSecretId);
    }

    /**
     * Measurement name for influx
     * 
     */
    @Import(name="measurementName")
    private @Nullable Output<String> measurementName;

    /**
     * @return Measurement name for influx
     * 
     */
    public Optional<Output<String>> measurementName() {
        return Optional.ofNullable(this.measurementName);
    }

    /**
     * Object storage namespace
     * 
     */
    @Import(name="namespace")
    private @Nullable Output<String> namespace;

    /**
     * @return Object storage namespace
     * 
     */
    public Optional<Output<String>> namespace() {
        return Optional.ofNullable(this.namespace);
    }

    /**
     * File name
     * 
     */
    @Import(name="object")
    private @Nullable Output<String> object;

    /**
     * @return File name
     * 
     */
    public Optional<Output<String>> object() {
        return Optional.ofNullable(this.object);
    }

    /**
     * OCID of the secret that contains jdbc properties file of ATP wallet
     * 
     */
    @Import(name="ojdbcFileSecretId")
    private @Nullable Output<String> ojdbcFileSecretId;

    /**
     * @return OCID of the secret that contains jdbc properties file of ATP wallet
     * 
     */
    public Optional<Output<String>> ojdbcFileSecretId() {
        return Optional.ofNullable(this.ojdbcFileSecretId);
    }

    /**
     * Password Secret Id for the influx connection
     * 
     */
    @Import(name="passwordSecretId")
    private @Nullable Output<String> passwordSecretId;

    /**
     * @return Password Secret Id for the influx connection
     * 
     */
    public Optional<Output<String>> passwordSecretId() {
        return Optional.ofNullable(this.passwordSecretId);
    }

    /**
     * atp database table name
     * 
     */
    @Import(name="tableName")
    private @Nullable Output<String> tableName;

    /**
     * @return atp database table name
     * 
     */
    public Optional<Output<String>> tableName() {
        return Optional.ofNullable(this.tableName);
    }

    /**
     * OCID of the secret that contains the tnsnames file of ATP wallet
     * 
     */
    @Import(name="tnsnamesFileSecretId")
    private @Nullable Output<String> tnsnamesFileSecretId;

    /**
     * @return OCID of the secret that contains the tnsnames file of ATP wallet
     * 
     */
    public Optional<Output<String>> tnsnamesFileSecretId() {
        return Optional.ofNullable(this.tnsnamesFileSecretId);
    }

    /**
     * OCID of the secret containing truststore.jks file of the ATP wallet
     * 
     */
    @Import(name="truststoreFileSecretId")
    private @Nullable Output<String> truststoreFileSecretId;

    /**
     * @return OCID of the secret containing truststore.jks file of the ATP wallet
     * 
     */
    public Optional<Output<String>> truststoreFileSecretId() {
        return Optional.ofNullable(this.truststoreFileSecretId);
    }

    /**
     * public IP address and port to influx DB
     * 
     */
    @Import(name="url")
    private @Nullable Output<String> url;

    /**
     * @return public IP address and port to influx DB
     * 
     */
    public Optional<Output<String>> url() {
        return Optional.ofNullable(this.url);
    }

    /**
     * Username for connection to Influx
     * 
     */
    @Import(name="userName")
    private @Nullable Output<String> userName;

    /**
     * @return Username for connection to Influx
     * 
     */
    public Optional<Output<String>> userName() {
        return Optional.ofNullable(this.userName);
    }

    /**
     * Possible data sources
     * 
     */
    @Import(name="versionSpecificDetails")
    private @Nullable Output<DataAssetDataSourceDetailsVersionSpecificDetailsArgs> versionSpecificDetails;

    /**
     * @return Possible data sources
     * 
     */
    public Optional<Output<DataAssetDataSourceDetailsVersionSpecificDetailsArgs>> versionSpecificDetails() {
        return Optional.ofNullable(this.versionSpecificDetails);
    }

    /**
     * wallet password Secret ID in String format
     * 
     */
    @Import(name="walletPasswordSecretId")
    private @Nullable Output<String> walletPasswordSecretId;

    /**
     * @return wallet password Secret ID in String format
     * 
     */
    public Optional<Output<String>> walletPasswordSecretId() {
        return Optional.ofNullable(this.walletPasswordSecretId);
    }

    private DataAssetDataSourceDetailsArgs() {}

    private DataAssetDataSourceDetailsArgs(DataAssetDataSourceDetailsArgs $) {
        this.atpPasswordSecretId = $.atpPasswordSecretId;
        this.atpUserName = $.atpUserName;
        this.bucket = $.bucket;
        this.cwalletFileSecretId = $.cwalletFileSecretId;
        this.dataSourceType = $.dataSourceType;
        this.databaseName = $.databaseName;
        this.ewalletFileSecretId = $.ewalletFileSecretId;
        this.keyStoreFileSecretId = $.keyStoreFileSecretId;
        this.measurementName = $.measurementName;
        this.namespace = $.namespace;
        this.object = $.object;
        this.ojdbcFileSecretId = $.ojdbcFileSecretId;
        this.passwordSecretId = $.passwordSecretId;
        this.tableName = $.tableName;
        this.tnsnamesFileSecretId = $.tnsnamesFileSecretId;
        this.truststoreFileSecretId = $.truststoreFileSecretId;
        this.url = $.url;
        this.userName = $.userName;
        this.versionSpecificDetails = $.versionSpecificDetails;
        this.walletPasswordSecretId = $.walletPasswordSecretId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DataAssetDataSourceDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DataAssetDataSourceDetailsArgs $;

        public Builder() {
            $ = new DataAssetDataSourceDetailsArgs();
        }

        public Builder(DataAssetDataSourceDetailsArgs defaults) {
            $ = new DataAssetDataSourceDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param atpPasswordSecretId atp db password Secret Id
         * 
         * @return builder
         * 
         */
        public Builder atpPasswordSecretId(@Nullable Output<String> atpPasswordSecretId) {
            $.atpPasswordSecretId = atpPasswordSecretId;
            return this;
        }

        /**
         * @param atpPasswordSecretId atp db password Secret Id
         * 
         * @return builder
         * 
         */
        public Builder atpPasswordSecretId(String atpPasswordSecretId) {
            return atpPasswordSecretId(Output.of(atpPasswordSecretId));
        }

        /**
         * @param atpUserName atp db user name
         * 
         * @return builder
         * 
         */
        public Builder atpUserName(@Nullable Output<String> atpUserName) {
            $.atpUserName = atpUserName;
            return this;
        }

        /**
         * @param atpUserName atp db user name
         * 
         * @return builder
         * 
         */
        public Builder atpUserName(String atpUserName) {
            return atpUserName(Output.of(atpUserName));
        }

        /**
         * @param bucket Object storage bucket name
         * 
         * @return builder
         * 
         */
        public Builder bucket(@Nullable Output<String> bucket) {
            $.bucket = bucket;
            return this;
        }

        /**
         * @param bucket Object storage bucket name
         * 
         * @return builder
         * 
         */
        public Builder bucket(String bucket) {
            return bucket(Output.of(bucket));
        }

        /**
         * @param cwalletFileSecretId OCID of the secret containing the containers certificates of ATP wallet
         * 
         * @return builder
         * 
         */
        public Builder cwalletFileSecretId(@Nullable Output<String> cwalletFileSecretId) {
            $.cwalletFileSecretId = cwalletFileSecretId;
            return this;
        }

        /**
         * @param cwalletFileSecretId OCID of the secret containing the containers certificates of ATP wallet
         * 
         * @return builder
         * 
         */
        public Builder cwalletFileSecretId(String cwalletFileSecretId) {
            return cwalletFileSecretId(Output.of(cwalletFileSecretId));
        }

        /**
         * @param dataSourceType Data source type where actually data asset is being stored
         * 
         * @return builder
         * 
         */
        public Builder dataSourceType(Output<String> dataSourceType) {
            $.dataSourceType = dataSourceType;
            return this;
        }

        /**
         * @param dataSourceType Data source type where actually data asset is being stored
         * 
         * @return builder
         * 
         */
        public Builder dataSourceType(String dataSourceType) {
            return dataSourceType(Output.of(dataSourceType));
        }

        /**
         * @param databaseName atp database name
         * 
         * @return builder
         * 
         */
        public Builder databaseName(@Nullable Output<String> databaseName) {
            $.databaseName = databaseName;
            return this;
        }

        /**
         * @param databaseName atp database name
         * 
         * @return builder
         * 
         */
        public Builder databaseName(String databaseName) {
            return databaseName(Output.of(databaseName));
        }

        /**
         * @param ewalletFileSecretId OCID of the secret containing the PDB&#39;S certificates of ATP wallet
         * 
         * @return builder
         * 
         */
        public Builder ewalletFileSecretId(@Nullable Output<String> ewalletFileSecretId) {
            $.ewalletFileSecretId = ewalletFileSecretId;
            return this;
        }

        /**
         * @param ewalletFileSecretId OCID of the secret containing the PDB&#39;S certificates of ATP wallet
         * 
         * @return builder
         * 
         */
        public Builder ewalletFileSecretId(String ewalletFileSecretId) {
            return ewalletFileSecretId(Output.of(ewalletFileSecretId));
        }

        /**
         * @param keyStoreFileSecretId OCID of the secret containing Keystore.jks file of the ATP wallet
         * 
         * @return builder
         * 
         */
        public Builder keyStoreFileSecretId(@Nullable Output<String> keyStoreFileSecretId) {
            $.keyStoreFileSecretId = keyStoreFileSecretId;
            return this;
        }

        /**
         * @param keyStoreFileSecretId OCID of the secret containing Keystore.jks file of the ATP wallet
         * 
         * @return builder
         * 
         */
        public Builder keyStoreFileSecretId(String keyStoreFileSecretId) {
            return keyStoreFileSecretId(Output.of(keyStoreFileSecretId));
        }

        /**
         * @param measurementName Measurement name for influx
         * 
         * @return builder
         * 
         */
        public Builder measurementName(@Nullable Output<String> measurementName) {
            $.measurementName = measurementName;
            return this;
        }

        /**
         * @param measurementName Measurement name for influx
         * 
         * @return builder
         * 
         */
        public Builder measurementName(String measurementName) {
            return measurementName(Output.of(measurementName));
        }

        /**
         * @param namespace Object storage namespace
         * 
         * @return builder
         * 
         */
        public Builder namespace(@Nullable Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace Object storage namespace
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        /**
         * @param object File name
         * 
         * @return builder
         * 
         */
        public Builder object(@Nullable Output<String> object) {
            $.object = object;
            return this;
        }

        /**
         * @param object File name
         * 
         * @return builder
         * 
         */
        public Builder object(String object) {
            return object(Output.of(object));
        }

        /**
         * @param ojdbcFileSecretId OCID of the secret that contains jdbc properties file of ATP wallet
         * 
         * @return builder
         * 
         */
        public Builder ojdbcFileSecretId(@Nullable Output<String> ojdbcFileSecretId) {
            $.ojdbcFileSecretId = ojdbcFileSecretId;
            return this;
        }

        /**
         * @param ojdbcFileSecretId OCID of the secret that contains jdbc properties file of ATP wallet
         * 
         * @return builder
         * 
         */
        public Builder ojdbcFileSecretId(String ojdbcFileSecretId) {
            return ojdbcFileSecretId(Output.of(ojdbcFileSecretId));
        }

        /**
         * @param passwordSecretId Password Secret Id for the influx connection
         * 
         * @return builder
         * 
         */
        public Builder passwordSecretId(@Nullable Output<String> passwordSecretId) {
            $.passwordSecretId = passwordSecretId;
            return this;
        }

        /**
         * @param passwordSecretId Password Secret Id for the influx connection
         * 
         * @return builder
         * 
         */
        public Builder passwordSecretId(String passwordSecretId) {
            return passwordSecretId(Output.of(passwordSecretId));
        }

        /**
         * @param tableName atp database table name
         * 
         * @return builder
         * 
         */
        public Builder tableName(@Nullable Output<String> tableName) {
            $.tableName = tableName;
            return this;
        }

        /**
         * @param tableName atp database table name
         * 
         * @return builder
         * 
         */
        public Builder tableName(String tableName) {
            return tableName(Output.of(tableName));
        }

        /**
         * @param tnsnamesFileSecretId OCID of the secret that contains the tnsnames file of ATP wallet
         * 
         * @return builder
         * 
         */
        public Builder tnsnamesFileSecretId(@Nullable Output<String> tnsnamesFileSecretId) {
            $.tnsnamesFileSecretId = tnsnamesFileSecretId;
            return this;
        }

        /**
         * @param tnsnamesFileSecretId OCID of the secret that contains the tnsnames file of ATP wallet
         * 
         * @return builder
         * 
         */
        public Builder tnsnamesFileSecretId(String tnsnamesFileSecretId) {
            return tnsnamesFileSecretId(Output.of(tnsnamesFileSecretId));
        }

        /**
         * @param truststoreFileSecretId OCID of the secret containing truststore.jks file of the ATP wallet
         * 
         * @return builder
         * 
         */
        public Builder truststoreFileSecretId(@Nullable Output<String> truststoreFileSecretId) {
            $.truststoreFileSecretId = truststoreFileSecretId;
            return this;
        }

        /**
         * @param truststoreFileSecretId OCID of the secret containing truststore.jks file of the ATP wallet
         * 
         * @return builder
         * 
         */
        public Builder truststoreFileSecretId(String truststoreFileSecretId) {
            return truststoreFileSecretId(Output.of(truststoreFileSecretId));
        }

        /**
         * @param url public IP address and port to influx DB
         * 
         * @return builder
         * 
         */
        public Builder url(@Nullable Output<String> url) {
            $.url = url;
            return this;
        }

        /**
         * @param url public IP address and port to influx DB
         * 
         * @return builder
         * 
         */
        public Builder url(String url) {
            return url(Output.of(url));
        }

        /**
         * @param userName Username for connection to Influx
         * 
         * @return builder
         * 
         */
        public Builder userName(@Nullable Output<String> userName) {
            $.userName = userName;
            return this;
        }

        /**
         * @param userName Username for connection to Influx
         * 
         * @return builder
         * 
         */
        public Builder userName(String userName) {
            return userName(Output.of(userName));
        }

        /**
         * @param versionSpecificDetails Possible data sources
         * 
         * @return builder
         * 
         */
        public Builder versionSpecificDetails(@Nullable Output<DataAssetDataSourceDetailsVersionSpecificDetailsArgs> versionSpecificDetails) {
            $.versionSpecificDetails = versionSpecificDetails;
            return this;
        }

        /**
         * @param versionSpecificDetails Possible data sources
         * 
         * @return builder
         * 
         */
        public Builder versionSpecificDetails(DataAssetDataSourceDetailsVersionSpecificDetailsArgs versionSpecificDetails) {
            return versionSpecificDetails(Output.of(versionSpecificDetails));
        }

        /**
         * @param walletPasswordSecretId wallet password Secret ID in String format
         * 
         * @return builder
         * 
         */
        public Builder walletPasswordSecretId(@Nullable Output<String> walletPasswordSecretId) {
            $.walletPasswordSecretId = walletPasswordSecretId;
            return this;
        }

        /**
         * @param walletPasswordSecretId wallet password Secret ID in String format
         * 
         * @return builder
         * 
         */
        public Builder walletPasswordSecretId(String walletPasswordSecretId) {
            return walletPasswordSecretId(Output.of(walletPasswordSecretId));
        }

        public DataAssetDataSourceDetailsArgs build() {
            if ($.dataSourceType == null) {
                throw new MissingRequiredPropertyException("DataAssetDataSourceDetailsArgs", "dataSourceType");
            }
            return $;
        }
    }

}
