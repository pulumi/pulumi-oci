// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigConnectorDetail;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetail;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfig {
    /**
     * @return The connector details required to connect to an Oracle cloud database.
     * 
     */
    private List<GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigConnectorDetail> connectorDetails;
    /**
     * @return The connection details required to connect to the database.
     * 
     */
    private List<GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetail> databaseConnectionDetails;
    /**
     * @return The name of the Database Management feature.
     * 
     */
    private String feature;
    /**
     * @return The list of statuses for Database Management features.
     * 
     */
    private String featureStatus;
    /**
     * @return The Oracle license model that applies to the external database.
     * 
     */
    private String licenseModel;

    private GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfig() {}
    /**
     * @return The connector details required to connect to an Oracle cloud database.
     * 
     */
    public List<GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigConnectorDetail> connectorDetails() {
        return this.connectorDetails;
    }
    /**
     * @return The connection details required to connect to the database.
     * 
     */
    public List<GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetail> databaseConnectionDetails() {
        return this.databaseConnectionDetails;
    }
    /**
     * @return The name of the Database Management feature.
     * 
     */
    public String feature() {
        return this.feature;
    }
    /**
     * @return The list of statuses for Database Management features.
     * 
     */
    public String featureStatus() {
        return this.featureStatus;
    }
    /**
     * @return The Oracle license model that applies to the external database.
     * 
     */
    public String licenseModel() {
        return this.licenseModel;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigConnectorDetail> connectorDetails;
        private List<GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetail> databaseConnectionDetails;
        private String feature;
        private String featureStatus;
        private String licenseModel;
        public Builder() {}
        public Builder(GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.connectorDetails = defaults.connectorDetails;
    	      this.databaseConnectionDetails = defaults.databaseConnectionDetails;
    	      this.feature = defaults.feature;
    	      this.featureStatus = defaults.featureStatus;
    	      this.licenseModel = defaults.licenseModel;
        }

        @CustomType.Setter
        public Builder connectorDetails(List<GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigConnectorDetail> connectorDetails) {
            if (connectorDetails == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfig", "connectorDetails");
            }
            this.connectorDetails = connectorDetails;
            return this;
        }
        public Builder connectorDetails(GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigConnectorDetail... connectorDetails) {
            return connectorDetails(List.of(connectorDetails));
        }
        @CustomType.Setter
        public Builder databaseConnectionDetails(List<GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetail> databaseConnectionDetails) {
            if (databaseConnectionDetails == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfig", "databaseConnectionDetails");
            }
            this.databaseConnectionDetails = databaseConnectionDetails;
            return this;
        }
        public Builder databaseConnectionDetails(GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfigDatabaseConnectionDetail... databaseConnectionDetails) {
            return databaseConnectionDetails(List.of(databaseConnectionDetails));
        }
        @CustomType.Setter
        public Builder feature(String feature) {
            if (feature == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfig", "feature");
            }
            this.feature = feature;
            return this;
        }
        @CustomType.Setter
        public Builder featureStatus(String featureStatus) {
            if (featureStatus == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfig", "featureStatus");
            }
            this.featureStatus = featureStatus;
            return this;
        }
        @CustomType.Setter
        public Builder licenseModel(String licenseModel) {
            if (licenseModel == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfig", "licenseModel");
            }
            this.licenseModel = licenseModel;
            return this;
        }
        public GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfig build() {
            final var _resultValue = new GetManagedDatabasesManagedDatabaseCollectionItemDbmgmtFeatureConfig();
            _resultValue.connectorDetails = connectorDetails;
            _resultValue.databaseConnectionDetails = databaseConnectionDetails;
            _resultValue.feature = feature;
            _resultValue.featureStatus = featureStatus;
            _resultValue.licenseModel = licenseModel;
            return _resultValue;
        }
    }
}
