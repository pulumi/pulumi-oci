// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalDbSystemConnectorConnectionInfoConnectionCredential;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalDbSystemConnectorConnectionInfoConnectionString;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalDbSystemConnectorConnectionInfoDatabaseCredential;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetExternalDbSystemConnectorConnectionInfo {
    /**
     * @return The component type.
     * 
     */
    private String componentType;
    /**
     * @return The credentials used to connect to the ASM instance. Currently only the `DETAILS` type is supported for creating MACS connector credentials.
     * 
     */
    private List<GetExternalDbSystemConnectorConnectionInfoConnectionCredential> connectionCredentials;
    /**
     * @return The Oracle Database connection string.
     * 
     */
    private List<GetExternalDbSystemConnectorConnectionInfoConnectionString> connectionStrings;
    /**
     * @return The credential to connect to the database to perform tablespace administration tasks.
     * 
     */
    private List<GetExternalDbSystemConnectorConnectionInfoDatabaseCredential> databaseCredentials;

    private GetExternalDbSystemConnectorConnectionInfo() {}
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
    public List<GetExternalDbSystemConnectorConnectionInfoConnectionCredential> connectionCredentials() {
        return this.connectionCredentials;
    }
    /**
     * @return The Oracle Database connection string.
     * 
     */
    public List<GetExternalDbSystemConnectorConnectionInfoConnectionString> connectionStrings() {
        return this.connectionStrings;
    }
    /**
     * @return The credential to connect to the database to perform tablespace administration tasks.
     * 
     */
    public List<GetExternalDbSystemConnectorConnectionInfoDatabaseCredential> databaseCredentials() {
        return this.databaseCredentials;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalDbSystemConnectorConnectionInfo defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String componentType;
        private List<GetExternalDbSystemConnectorConnectionInfoConnectionCredential> connectionCredentials;
        private List<GetExternalDbSystemConnectorConnectionInfoConnectionString> connectionStrings;
        private List<GetExternalDbSystemConnectorConnectionInfoDatabaseCredential> databaseCredentials;
        public Builder() {}
        public Builder(GetExternalDbSystemConnectorConnectionInfo defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.componentType = defaults.componentType;
    	      this.connectionCredentials = defaults.connectionCredentials;
    	      this.connectionStrings = defaults.connectionStrings;
    	      this.databaseCredentials = defaults.databaseCredentials;
        }

        @CustomType.Setter
        public Builder componentType(String componentType) {
            if (componentType == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorConnectionInfo", "componentType");
            }
            this.componentType = componentType;
            return this;
        }
        @CustomType.Setter
        public Builder connectionCredentials(List<GetExternalDbSystemConnectorConnectionInfoConnectionCredential> connectionCredentials) {
            if (connectionCredentials == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorConnectionInfo", "connectionCredentials");
            }
            this.connectionCredentials = connectionCredentials;
            return this;
        }
        public Builder connectionCredentials(GetExternalDbSystemConnectorConnectionInfoConnectionCredential... connectionCredentials) {
            return connectionCredentials(List.of(connectionCredentials));
        }
        @CustomType.Setter
        public Builder connectionStrings(List<GetExternalDbSystemConnectorConnectionInfoConnectionString> connectionStrings) {
            if (connectionStrings == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorConnectionInfo", "connectionStrings");
            }
            this.connectionStrings = connectionStrings;
            return this;
        }
        public Builder connectionStrings(GetExternalDbSystemConnectorConnectionInfoConnectionString... connectionStrings) {
            return connectionStrings(List.of(connectionStrings));
        }
        @CustomType.Setter
        public Builder databaseCredentials(List<GetExternalDbSystemConnectorConnectionInfoDatabaseCredential> databaseCredentials) {
            if (databaseCredentials == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemConnectorConnectionInfo", "databaseCredentials");
            }
            this.databaseCredentials = databaseCredentials;
            return this;
        }
        public Builder databaseCredentials(GetExternalDbSystemConnectorConnectionInfoDatabaseCredential... databaseCredentials) {
            return databaseCredentials(List.of(databaseCredentials));
        }
        public GetExternalDbSystemConnectorConnectionInfo build() {
            final var _resultValue = new GetExternalDbSystemConnectorConnectionInfo();
            _resultValue.componentType = componentType;
            _resultValue.connectionCredentials = connectionCredentials;
            _resultValue.connectionStrings = connectionStrings;
            _resultValue.databaseCredentials = databaseCredentials;
            return _resultValue;
        }
    }
}
