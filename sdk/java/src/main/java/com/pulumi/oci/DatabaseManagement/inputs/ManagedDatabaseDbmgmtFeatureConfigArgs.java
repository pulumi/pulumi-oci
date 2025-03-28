// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DatabaseManagement.inputs.ManagedDatabaseDbmgmtFeatureConfigConnectorDetailArgs;
import com.pulumi.oci.DatabaseManagement.inputs.ManagedDatabaseDbmgmtFeatureConfigDatabaseConnectionDetailArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ManagedDatabaseDbmgmtFeatureConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final ManagedDatabaseDbmgmtFeatureConfigArgs Empty = new ManagedDatabaseDbmgmtFeatureConfigArgs();

    /**
     * The connector details required to connect to an Oracle cloud database.
     * 
     */
    @Import(name="connectorDetails")
    private @Nullable Output<List<ManagedDatabaseDbmgmtFeatureConfigConnectorDetailArgs>> connectorDetails;

    /**
     * @return The connector details required to connect to an Oracle cloud database.
     * 
     */
    public Optional<Output<List<ManagedDatabaseDbmgmtFeatureConfigConnectorDetailArgs>>> connectorDetails() {
        return Optional.ofNullable(this.connectorDetails);
    }

    /**
     * The connection details required to connect to the database.
     * 
     */
    @Import(name="databaseConnectionDetails")
    private @Nullable Output<List<ManagedDatabaseDbmgmtFeatureConfigDatabaseConnectionDetailArgs>> databaseConnectionDetails;

    /**
     * @return The connection details required to connect to the database.
     * 
     */
    public Optional<Output<List<ManagedDatabaseDbmgmtFeatureConfigDatabaseConnectionDetailArgs>>> databaseConnectionDetails() {
        return Optional.ofNullable(this.databaseConnectionDetails);
    }

    /**
     * The name of the Database Management feature.
     * 
     */
    @Import(name="feature")
    private @Nullable Output<String> feature;

    /**
     * @return The name of the Database Management feature.
     * 
     */
    public Optional<Output<String>> feature() {
        return Optional.ofNullable(this.feature);
    }

    /**
     * The list of statuses for Database Management features.
     * 
     */
    @Import(name="featureStatus")
    private @Nullable Output<String> featureStatus;

    /**
     * @return The list of statuses for Database Management features.
     * 
     */
    public Optional<Output<String>> featureStatus() {
        return Optional.ofNullable(this.featureStatus);
    }

    /**
     * The Oracle license model that applies to the external database.
     * 
     */
    @Import(name="licenseModel")
    private @Nullable Output<String> licenseModel;

    /**
     * @return The Oracle license model that applies to the external database.
     * 
     */
    public Optional<Output<String>> licenseModel() {
        return Optional.ofNullable(this.licenseModel);
    }

    private ManagedDatabaseDbmgmtFeatureConfigArgs() {}

    private ManagedDatabaseDbmgmtFeatureConfigArgs(ManagedDatabaseDbmgmtFeatureConfigArgs $) {
        this.connectorDetails = $.connectorDetails;
        this.databaseConnectionDetails = $.databaseConnectionDetails;
        this.feature = $.feature;
        this.featureStatus = $.featureStatus;
        this.licenseModel = $.licenseModel;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ManagedDatabaseDbmgmtFeatureConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ManagedDatabaseDbmgmtFeatureConfigArgs $;

        public Builder() {
            $ = new ManagedDatabaseDbmgmtFeatureConfigArgs();
        }

        public Builder(ManagedDatabaseDbmgmtFeatureConfigArgs defaults) {
            $ = new ManagedDatabaseDbmgmtFeatureConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param connectorDetails The connector details required to connect to an Oracle cloud database.
         * 
         * @return builder
         * 
         */
        public Builder connectorDetails(@Nullable Output<List<ManagedDatabaseDbmgmtFeatureConfigConnectorDetailArgs>> connectorDetails) {
            $.connectorDetails = connectorDetails;
            return this;
        }

        /**
         * @param connectorDetails The connector details required to connect to an Oracle cloud database.
         * 
         * @return builder
         * 
         */
        public Builder connectorDetails(List<ManagedDatabaseDbmgmtFeatureConfigConnectorDetailArgs> connectorDetails) {
            return connectorDetails(Output.of(connectorDetails));
        }

        /**
         * @param connectorDetails The connector details required to connect to an Oracle cloud database.
         * 
         * @return builder
         * 
         */
        public Builder connectorDetails(ManagedDatabaseDbmgmtFeatureConfigConnectorDetailArgs... connectorDetails) {
            return connectorDetails(List.of(connectorDetails));
        }

        /**
         * @param databaseConnectionDetails The connection details required to connect to the database.
         * 
         * @return builder
         * 
         */
        public Builder databaseConnectionDetails(@Nullable Output<List<ManagedDatabaseDbmgmtFeatureConfigDatabaseConnectionDetailArgs>> databaseConnectionDetails) {
            $.databaseConnectionDetails = databaseConnectionDetails;
            return this;
        }

        /**
         * @param databaseConnectionDetails The connection details required to connect to the database.
         * 
         * @return builder
         * 
         */
        public Builder databaseConnectionDetails(List<ManagedDatabaseDbmgmtFeatureConfigDatabaseConnectionDetailArgs> databaseConnectionDetails) {
            return databaseConnectionDetails(Output.of(databaseConnectionDetails));
        }

        /**
         * @param databaseConnectionDetails The connection details required to connect to the database.
         * 
         * @return builder
         * 
         */
        public Builder databaseConnectionDetails(ManagedDatabaseDbmgmtFeatureConfigDatabaseConnectionDetailArgs... databaseConnectionDetails) {
            return databaseConnectionDetails(List.of(databaseConnectionDetails));
        }

        /**
         * @param feature The name of the Database Management feature.
         * 
         * @return builder
         * 
         */
        public Builder feature(@Nullable Output<String> feature) {
            $.feature = feature;
            return this;
        }

        /**
         * @param feature The name of the Database Management feature.
         * 
         * @return builder
         * 
         */
        public Builder feature(String feature) {
            return feature(Output.of(feature));
        }

        /**
         * @param featureStatus The list of statuses for Database Management features.
         * 
         * @return builder
         * 
         */
        public Builder featureStatus(@Nullable Output<String> featureStatus) {
            $.featureStatus = featureStatus;
            return this;
        }

        /**
         * @param featureStatus The list of statuses for Database Management features.
         * 
         * @return builder
         * 
         */
        public Builder featureStatus(String featureStatus) {
            return featureStatus(Output.of(featureStatus));
        }

        /**
         * @param licenseModel The Oracle license model that applies to the external database.
         * 
         * @return builder
         * 
         */
        public Builder licenseModel(@Nullable Output<String> licenseModel) {
            $.licenseModel = licenseModel;
            return this;
        }

        /**
         * @param licenseModel The Oracle license model that applies to the external database.
         * 
         * @return builder
         * 
         */
        public Builder licenseModel(String licenseModel) {
            return licenseModel(Output.of(licenseModel));
        }

        public ManagedDatabaseDbmgmtFeatureConfigArgs build() {
            return $;
        }
    }

}
