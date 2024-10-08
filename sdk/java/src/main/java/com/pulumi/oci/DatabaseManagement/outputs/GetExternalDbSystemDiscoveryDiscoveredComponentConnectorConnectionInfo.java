// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfoConnectionCredential;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfoConnectionString;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfoDatabaseCredential;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfo {
    /**
     * @return The component type.
     * 
     */
    private String componentType;
    /**
     * @return The credentials used to connect to the ASM instance. Currently only the `DETAILS` type is supported for creating MACS connector credentials.
     * 
     */
    private List<GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfoConnectionCredential> connectionCredentials;
    /**
     * @return The Oracle Database connection string.
     * 
     */
    private List<GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfoConnectionString> connectionStrings;
    /**
     * @return The credential to connect to the database to perform tablespace administration tasks.
     * 
     */
    private List<GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfoDatabaseCredential> databaseCredentials;

    private GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfo() {}
    /**
     * @return The component type.
     * 
     */
    public String componentType() {
        return this.componentType;
    }
    /**
     * @return The credentials used to connect to the ASM instance. Currently only the `DETAILS` type is supported for creating MACS connector credentials.
     * 
     */
    public List<GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfoConnectionCredential> connectionCredentials() {
        return this.connectionCredentials;
    }
    /**
     * @return The Oracle Database connection string.
     * 
     */
    public List<GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfoConnectionString> connectionStrings() {
        return this.connectionStrings;
    }
    /**
     * @return The credential to connect to the database to perform tablespace administration tasks.
     * 
     */
    public List<GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfoDatabaseCredential> databaseCredentials() {
        return this.databaseCredentials;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfo defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String componentType;
        private List<GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfoConnectionCredential> connectionCredentials;
        private List<GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfoConnectionString> connectionStrings;
        private List<GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfoDatabaseCredential> databaseCredentials;
        public Builder() {}
        public Builder(GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfo defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.componentType = defaults.componentType;
    	      this.connectionCredentials = defaults.connectionCredentials;
    	      this.connectionStrings = defaults.connectionStrings;
    	      this.databaseCredentials = defaults.databaseCredentials;
        }

        @CustomType.Setter
        public Builder componentType(String componentType) {
            if (componentType == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfo", "componentType");
            }
            this.componentType = componentType;
            return this;
        }
        @CustomType.Setter
        public Builder connectionCredentials(List<GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfoConnectionCredential> connectionCredentials) {
            if (connectionCredentials == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfo", "connectionCredentials");
            }
            this.connectionCredentials = connectionCredentials;
            return this;
        }
        public Builder connectionCredentials(GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfoConnectionCredential... connectionCredentials) {
            return connectionCredentials(List.of(connectionCredentials));
        }
        @CustomType.Setter
        public Builder connectionStrings(List<GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfoConnectionString> connectionStrings) {
            if (connectionStrings == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfo", "connectionStrings");
            }
            this.connectionStrings = connectionStrings;
            return this;
        }
        public Builder connectionStrings(GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfoConnectionString... connectionStrings) {
            return connectionStrings(List.of(connectionStrings));
        }
        @CustomType.Setter
        public Builder databaseCredentials(List<GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfoDatabaseCredential> databaseCredentials) {
            if (databaseCredentials == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfo", "databaseCredentials");
            }
            this.databaseCredentials = databaseCredentials;
            return this;
        }
        public Builder databaseCredentials(GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfoDatabaseCredential... databaseCredentials) {
            return databaseCredentials(List.of(databaseCredentials));
        }
        public GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfo build() {
            final var _resultValue = new GetExternalDbSystemDiscoveryDiscoveredComponentConnectorConnectionInfo();
            _resultValue.componentType = componentType;
            _resultValue.connectionCredentials = connectionCredentials;
            _resultValue.connectionStrings = connectionStrings;
            _resultValue.databaseCredentials = databaseCredentials;
            return _resultValue;
        }
    }
}
