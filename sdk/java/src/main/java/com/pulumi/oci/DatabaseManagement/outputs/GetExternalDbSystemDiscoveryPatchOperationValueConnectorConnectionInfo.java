// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalDbSystemDiscoveryPatchOperationValueConnectorConnectionInfoConnectionCredential;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalDbSystemDiscoveryPatchOperationValueConnectorConnectionInfoConnectionString;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetExternalDbSystemDiscoveryPatchOperationValueConnectorConnectionInfo {
    /**
     * @return The component type.
     * 
     */
    private String componentType;
    /**
     * @return The credentials used to connect to the ASM instance. Currently only the `DETAILS` type is supported for creating MACS connector credentials.
     * 
     */
    private List<GetExternalDbSystemDiscoveryPatchOperationValueConnectorConnectionInfoConnectionCredential> connectionCredentials;
    /**
     * @return The Oracle Database connection string.
     * 
     */
    private List<GetExternalDbSystemDiscoveryPatchOperationValueConnectorConnectionInfoConnectionString> connectionStrings;

    private GetExternalDbSystemDiscoveryPatchOperationValueConnectorConnectionInfo() {}
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
    public List<GetExternalDbSystemDiscoveryPatchOperationValueConnectorConnectionInfoConnectionCredential> connectionCredentials() {
        return this.connectionCredentials;
    }
    /**
     * @return The Oracle Database connection string.
     * 
     */
    public List<GetExternalDbSystemDiscoveryPatchOperationValueConnectorConnectionInfoConnectionString> connectionStrings() {
        return this.connectionStrings;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalDbSystemDiscoveryPatchOperationValueConnectorConnectionInfo defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String componentType;
        private List<GetExternalDbSystemDiscoveryPatchOperationValueConnectorConnectionInfoConnectionCredential> connectionCredentials;
        private List<GetExternalDbSystemDiscoveryPatchOperationValueConnectorConnectionInfoConnectionString> connectionStrings;
        public Builder() {}
        public Builder(GetExternalDbSystemDiscoveryPatchOperationValueConnectorConnectionInfo defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.componentType = defaults.componentType;
    	      this.connectionCredentials = defaults.connectionCredentials;
    	      this.connectionStrings = defaults.connectionStrings;
        }

        @CustomType.Setter
        public Builder componentType(String componentType) {
            this.componentType = Objects.requireNonNull(componentType);
            return this;
        }
        @CustomType.Setter
        public Builder connectionCredentials(List<GetExternalDbSystemDiscoveryPatchOperationValueConnectorConnectionInfoConnectionCredential> connectionCredentials) {
            this.connectionCredentials = Objects.requireNonNull(connectionCredentials);
            return this;
        }
        public Builder connectionCredentials(GetExternalDbSystemDiscoveryPatchOperationValueConnectorConnectionInfoConnectionCredential... connectionCredentials) {
            return connectionCredentials(List.of(connectionCredentials));
        }
        @CustomType.Setter
        public Builder connectionStrings(List<GetExternalDbSystemDiscoveryPatchOperationValueConnectorConnectionInfoConnectionString> connectionStrings) {
            this.connectionStrings = Objects.requireNonNull(connectionStrings);
            return this;
        }
        public Builder connectionStrings(GetExternalDbSystemDiscoveryPatchOperationValueConnectorConnectionInfoConnectionString... connectionStrings) {
            return connectionStrings(List.of(connectionStrings));
        }
        public GetExternalDbSystemDiscoveryPatchOperationValueConnectorConnectionInfo build() {
            final var o = new GetExternalDbSystemDiscoveryPatchOperationValueConnectorConnectionInfo();
            o.componentType = componentType;
            o.connectionCredentials = connectionCredentials;
            o.connectionStrings = connectionStrings;
            return o;
        }
    }
}