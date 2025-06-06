// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetTargetDatabasesTargetDatabaseConnectionOption {
    /**
     * @return The connection type used to connect to the database. Allowed values:
     * * PRIVATE_ENDPOINT - Represents connection through private endpoint in Data Safe.
     * * ONPREM_CONNECTOR - Represents connection through on-premises connector in Data Safe.
     * 
     */
    private String connectionType;
    /**
     * @return The OCID of the Data Safe private endpoint.
     * 
     */
    private String datasafePrivateEndpointId;
    /**
     * @return The OCID of the on-premises connector.
     * 
     */
    private String onPremConnectorId;

    private GetTargetDatabasesTargetDatabaseConnectionOption() {}
    /**
     * @return The connection type used to connect to the database. Allowed values:
     * * PRIVATE_ENDPOINT - Represents connection through private endpoint in Data Safe.
     * * ONPREM_CONNECTOR - Represents connection through on-premises connector in Data Safe.
     * 
     */
    public String connectionType() {
        return this.connectionType;
    }
    /**
     * @return The OCID of the Data Safe private endpoint.
     * 
     */
    public String datasafePrivateEndpointId() {
        return this.datasafePrivateEndpointId;
    }
    /**
     * @return The OCID of the on-premises connector.
     * 
     */
    public String onPremConnectorId() {
        return this.onPremConnectorId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetTargetDatabasesTargetDatabaseConnectionOption defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String connectionType;
        private String datasafePrivateEndpointId;
        private String onPremConnectorId;
        public Builder() {}
        public Builder(GetTargetDatabasesTargetDatabaseConnectionOption defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.connectionType = defaults.connectionType;
    	      this.datasafePrivateEndpointId = defaults.datasafePrivateEndpointId;
    	      this.onPremConnectorId = defaults.onPremConnectorId;
        }

        @CustomType.Setter
        public Builder connectionType(String connectionType) {
            if (connectionType == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabasesTargetDatabaseConnectionOption", "connectionType");
            }
            this.connectionType = connectionType;
            return this;
        }
        @CustomType.Setter
        public Builder datasafePrivateEndpointId(String datasafePrivateEndpointId) {
            if (datasafePrivateEndpointId == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabasesTargetDatabaseConnectionOption", "datasafePrivateEndpointId");
            }
            this.datasafePrivateEndpointId = datasafePrivateEndpointId;
            return this;
        }
        @CustomType.Setter
        public Builder onPremConnectorId(String onPremConnectorId) {
            if (onPremConnectorId == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabasesTargetDatabaseConnectionOption", "onPremConnectorId");
            }
            this.onPremConnectorId = onPremConnectorId;
            return this;
        }
        public GetTargetDatabasesTargetDatabaseConnectionOption build() {
            final var _resultValue = new GetTargetDatabasesTargetDatabaseConnectionOption();
            _resultValue.connectionType = connectionType;
            _resultValue.datasafePrivateEndpointId = datasafePrivateEndpointId;
            _resultValue.onPremConnectorId = onPremConnectorId;
            return _resultValue;
        }
    }
}
