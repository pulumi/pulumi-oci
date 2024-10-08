// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.outputs.AutonomousDatabaseAutonomousDatabaseDbmFeaturesManagementFeatureDetailsConnectorDetails;
import com.pulumi.oci.DatabaseManagement.outputs.AutonomousDatabaseAutonomousDatabaseDbmFeaturesManagementFeatureDetailsDatabaseConnectionDetails;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class AutonomousDatabaseAutonomousDatabaseDbmFeaturesManagementFeatureDetails {
    /**
     * @return The connector details required to connect to an Oracle cloud database.
     * 
     */
    private @Nullable AutonomousDatabaseAutonomousDatabaseDbmFeaturesManagementFeatureDetailsConnectorDetails connectorDetails;
    /**
     * @return The connection details required to connect to the database.
     * 
     */
    private @Nullable AutonomousDatabaseAutonomousDatabaseDbmFeaturesManagementFeatureDetailsDatabaseConnectionDetails databaseConnectionDetails;
    /**
     * @return The name of the Database Management feature.
     * 
     */
    private String feature;

    private AutonomousDatabaseAutonomousDatabaseDbmFeaturesManagementFeatureDetails() {}
    /**
     * @return The connector details required to connect to an Oracle cloud database.
     * 
     */
    public Optional<AutonomousDatabaseAutonomousDatabaseDbmFeaturesManagementFeatureDetailsConnectorDetails> connectorDetails() {
        return Optional.ofNullable(this.connectorDetails);
    }
    /**
     * @return The connection details required to connect to the database.
     * 
     */
    public Optional<AutonomousDatabaseAutonomousDatabaseDbmFeaturesManagementFeatureDetailsDatabaseConnectionDetails> databaseConnectionDetails() {
        return Optional.ofNullable(this.databaseConnectionDetails);
    }
    /**
     * @return The name of the Database Management feature.
     * 
     */
    public String feature() {
        return this.feature;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AutonomousDatabaseAutonomousDatabaseDbmFeaturesManagementFeatureDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable AutonomousDatabaseAutonomousDatabaseDbmFeaturesManagementFeatureDetailsConnectorDetails connectorDetails;
        private @Nullable AutonomousDatabaseAutonomousDatabaseDbmFeaturesManagementFeatureDetailsDatabaseConnectionDetails databaseConnectionDetails;
        private String feature;
        public Builder() {}
        public Builder(AutonomousDatabaseAutonomousDatabaseDbmFeaturesManagementFeatureDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.connectorDetails = defaults.connectorDetails;
    	      this.databaseConnectionDetails = defaults.databaseConnectionDetails;
    	      this.feature = defaults.feature;
        }

        @CustomType.Setter
        public Builder connectorDetails(@Nullable AutonomousDatabaseAutonomousDatabaseDbmFeaturesManagementFeatureDetailsConnectorDetails connectorDetails) {

            this.connectorDetails = connectorDetails;
            return this;
        }
        @CustomType.Setter
        public Builder databaseConnectionDetails(@Nullable AutonomousDatabaseAutonomousDatabaseDbmFeaturesManagementFeatureDetailsDatabaseConnectionDetails databaseConnectionDetails) {

            this.databaseConnectionDetails = databaseConnectionDetails;
            return this;
        }
        @CustomType.Setter
        public Builder feature(String feature) {
            if (feature == null) {
              throw new MissingRequiredPropertyException("AutonomousDatabaseAutonomousDatabaseDbmFeaturesManagementFeatureDetails", "feature");
            }
            this.feature = feature;
            return this;
        }
        public AutonomousDatabaseAutonomousDatabaseDbmFeaturesManagementFeatureDetails build() {
            final var _resultValue = new AutonomousDatabaseAutonomousDatabaseDbmFeaturesManagementFeatureDetails();
            _resultValue.connectorDetails = connectorDetails;
            _resultValue.databaseConnectionDetails = databaseConnectionDetails;
            _resultValue.feature = feature;
            return _resultValue;
        }
    }
}
