// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Database.outputs.GetExternalDatabaseConnectorConnectionCredential;
import com.pulumi.oci.Database.outputs.GetExternalDatabaseConnectorConnectionString;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetExternalDatabaseConnectorResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return Credentials used to connect to the database. Currently only the `DETAILS` type is supported for creating MACS connector crendentials.
     * 
     */
    private List<GetExternalDatabaseConnectorConnectionCredential> connectionCredentials;
    /**
     * @return The status of connectivity to the external database.
     * 
     */
    private String connectionStatus;
    /**
     * @return The Oracle Database connection string.
     * 
     */
    private List<GetExternalDatabaseConnectorConnectionString> connectionStrings;
    /**
     * @return The ID of the agent used for the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
     * 
     */
    private String connectorAgentId;
    /**
     * @return The type of connector used by the external database resource.
     * 
     */
    private String connectorType;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return The user-friendly name for the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails). The name does not have to be unique.
     * 
     */
    private String displayName;
    private String externalDatabaseConnectorId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database resource.
     * 
     */
    private String externalDatabaseId;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
     * 
     */
    private String id;
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The current lifecycle state of the external database connector resource.
     * 
     */
    private String state;
    /**
     * @return The date and time the `connectionStatus` of this external connector was last updated.
     * 
     */
    private String timeConnectionStatusLastUpdated;
    /**
     * @return The date and time the external connector was created.
     * 
     */
    private String timeCreated;

    private GetExternalDatabaseConnectorResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Credentials used to connect to the database. Currently only the `DETAILS` type is supported for creating MACS connector crendentials.
     * 
     */
    public List<GetExternalDatabaseConnectorConnectionCredential> connectionCredentials() {
        return this.connectionCredentials;
    }
    /**
     * @return The status of connectivity to the external database.
     * 
     */
    public String connectionStatus() {
        return this.connectionStatus;
    }
    /**
     * @return The Oracle Database connection string.
     * 
     */
    public List<GetExternalDatabaseConnectorConnectionString> connectionStrings() {
        return this.connectionStrings;
    }
    /**
     * @return The ID of the agent used for the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
     * 
     */
    public String connectorAgentId() {
        return this.connectorAgentId;
    }
    /**
     * @return The type of connector used by the external database resource.
     * 
     */
    public String connectorType() {
        return this.connectorType;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The user-friendly name for the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails). The name does not have to be unique.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    public String externalDatabaseConnectorId() {
        return this.externalDatabaseConnectorId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database resource.
     * 
     */
    public String externalDatabaseId() {
        return this.externalDatabaseId;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The current lifecycle state of the external database connector resource.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the `connectionStatus` of this external connector was last updated.
     * 
     */
    public String timeConnectionStatusLastUpdated() {
        return this.timeConnectionStatusLastUpdated;
    }
    /**
     * @return The date and time the external connector was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalDatabaseConnectorResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private List<GetExternalDatabaseConnectorConnectionCredential> connectionCredentials;
        private String connectionStatus;
        private List<GetExternalDatabaseConnectorConnectionString> connectionStrings;
        private String connectorAgentId;
        private String connectorType;
        private Map<String,Object> definedTags;
        private String displayName;
        private String externalDatabaseConnectorId;
        private String externalDatabaseId;
        private Map<String,Object> freeformTags;
        private String id;
        private String lifecycleDetails;
        private String state;
        private String timeConnectionStatusLastUpdated;
        private String timeCreated;
        public Builder() {}
        public Builder(GetExternalDatabaseConnectorResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.connectionCredentials = defaults.connectionCredentials;
    	      this.connectionStatus = defaults.connectionStatus;
    	      this.connectionStrings = defaults.connectionStrings;
    	      this.connectorAgentId = defaults.connectorAgentId;
    	      this.connectorType = defaults.connectorType;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.externalDatabaseConnectorId = defaults.externalDatabaseConnectorId;
    	      this.externalDatabaseId = defaults.externalDatabaseId;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.state = defaults.state;
    	      this.timeConnectionStatusLastUpdated = defaults.timeConnectionStatusLastUpdated;
    	      this.timeCreated = defaults.timeCreated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder connectionCredentials(List<GetExternalDatabaseConnectorConnectionCredential> connectionCredentials) {
            this.connectionCredentials = Objects.requireNonNull(connectionCredentials);
            return this;
        }
        public Builder connectionCredentials(GetExternalDatabaseConnectorConnectionCredential... connectionCredentials) {
            return connectionCredentials(List.of(connectionCredentials));
        }
        @CustomType.Setter
        public Builder connectionStatus(String connectionStatus) {
            this.connectionStatus = Objects.requireNonNull(connectionStatus);
            return this;
        }
        @CustomType.Setter
        public Builder connectionStrings(List<GetExternalDatabaseConnectorConnectionString> connectionStrings) {
            this.connectionStrings = Objects.requireNonNull(connectionStrings);
            return this;
        }
        public Builder connectionStrings(GetExternalDatabaseConnectorConnectionString... connectionStrings) {
            return connectionStrings(List.of(connectionStrings));
        }
        @CustomType.Setter
        public Builder connectorAgentId(String connectorAgentId) {
            this.connectorAgentId = Objects.requireNonNull(connectorAgentId);
            return this;
        }
        @CustomType.Setter
        public Builder connectorType(String connectorType) {
            this.connectorType = Objects.requireNonNull(connectorType);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder externalDatabaseConnectorId(String externalDatabaseConnectorId) {
            this.externalDatabaseConnectorId = Objects.requireNonNull(externalDatabaseConnectorId);
            return this;
        }
        @CustomType.Setter
        public Builder externalDatabaseId(String externalDatabaseId) {
            this.externalDatabaseId = Objects.requireNonNull(externalDatabaseId);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder timeConnectionStatusLastUpdated(String timeConnectionStatusLastUpdated) {
            this.timeConnectionStatusLastUpdated = Objects.requireNonNull(timeConnectionStatusLastUpdated);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public GetExternalDatabaseConnectorResult build() {
            final var o = new GetExternalDatabaseConnectorResult();
            o.compartmentId = compartmentId;
            o.connectionCredentials = connectionCredentials;
            o.connectionStatus = connectionStatus;
            o.connectionStrings = connectionStrings;
            o.connectorAgentId = connectorAgentId;
            o.connectorType = connectorType;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.externalDatabaseConnectorId = externalDatabaseConnectorId;
            o.externalDatabaseId = externalDatabaseId;
            o.freeformTags = freeformTags;
            o.id = id;
            o.lifecycleDetails = lifecycleDetails;
            o.state = state;
            o.timeConnectionStatusLastUpdated = timeConnectionStatusLastUpdated;
            o.timeCreated = timeCreated;
            return o;
        }
    }
}