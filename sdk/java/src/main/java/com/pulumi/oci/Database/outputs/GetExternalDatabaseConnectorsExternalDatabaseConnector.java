// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Database.outputs.GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionCredential;
import com.pulumi.oci.Database.outputs.GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionString;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetExternalDatabaseConnectorsExternalDatabaseConnector {
    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    private final String compartmentId;
    /**
     * @return Credentials used to connect to the database. Currently only the `DETAILS` type is supported for creating MACS connector crendentials.
     * 
     */
    private final List<GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionCredential> connectionCredentials;
    /**
     * @return The status of connectivity to the external database.
     * 
     */
    private final String connectionStatus;
    /**
     * @return The Oracle Database connection string.
     * 
     */
    private final List<GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionString> connectionStrings;
    /**
     * @return The ID of the agent used for the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
     * 
     */
    private final String connectorAgentId;
    /**
     * @return The type of connector used by the external database resource.
     * 
     */
    private final String connectorType;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    private final Map<String,Object> definedTags;
    /**
     * @return A filter to return only resources that match the entire display name given. The match is not case sensitive.
     * 
     */
    private final String displayName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database whose connectors will be listed.
     * 
     */
    private final String externalDatabaseId;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private final Map<String,Object> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
     * 
     */
    private final String id;
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    private final String lifecycleDetails;
    /**
     * @return A filter to return only resources that match the specified lifecycle state.
     * 
     */
    private final String state;
    /**
     * @return The date and time the `connectionStatus` of this external connector was last updated.
     * 
     */
    private final String timeConnectionStatusLastUpdated;
    /**
     * @return The date and time the external connector was created.
     * 
     */
    private final String timeCreated;

    @CustomType.Constructor
    private GetExternalDatabaseConnectorsExternalDatabaseConnector(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("connectionCredentials") List<GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionCredential> connectionCredentials,
        @CustomType.Parameter("connectionStatus") String connectionStatus,
        @CustomType.Parameter("connectionStrings") List<GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionString> connectionStrings,
        @CustomType.Parameter("connectorAgentId") String connectorAgentId,
        @CustomType.Parameter("connectorType") String connectorType,
        @CustomType.Parameter("definedTags") Map<String,Object> definedTags,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("externalDatabaseId") String externalDatabaseId,
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("lifecycleDetails") String lifecycleDetails,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("timeConnectionStatusLastUpdated") String timeConnectionStatusLastUpdated,
        @CustomType.Parameter("timeCreated") String timeCreated) {
        this.compartmentId = compartmentId;
        this.connectionCredentials = connectionCredentials;
        this.connectionStatus = connectionStatus;
        this.connectionStrings = connectionStrings;
        this.connectorAgentId = connectorAgentId;
        this.connectorType = connectorType;
        this.definedTags = definedTags;
        this.displayName = displayName;
        this.externalDatabaseId = externalDatabaseId;
        this.freeformTags = freeformTags;
        this.id = id;
        this.lifecycleDetails = lifecycleDetails;
        this.state = state;
        this.timeConnectionStatusLastUpdated = timeConnectionStatusLastUpdated;
        this.timeCreated = timeCreated;
    }

    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Credentials used to connect to the database. Currently only the `DETAILS` type is supported for creating MACS connector crendentials.
     * 
     */
    public List<GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionCredential> connectionCredentials() {
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
    public List<GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionString> connectionStrings() {
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
     * @return A filter to return only resources that match the entire display name given. The match is not case sensitive.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database whose connectors will be listed.
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
     * @return A filter to return only resources that match the specified lifecycle state.
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

    public static Builder builder(GetExternalDatabaseConnectorsExternalDatabaseConnector defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private List<GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionCredential> connectionCredentials;
        private String connectionStatus;
        private List<GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionString> connectionStrings;
        private String connectorAgentId;
        private String connectorType;
        private Map<String,Object> definedTags;
        private String displayName;
        private String externalDatabaseId;
        private Map<String,Object> freeformTags;
        private String id;
        private String lifecycleDetails;
        private String state;
        private String timeConnectionStatusLastUpdated;
        private String timeCreated;

        public Builder() {
    	      // Empty
        }

        public Builder(GetExternalDatabaseConnectorsExternalDatabaseConnector defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.connectionCredentials = defaults.connectionCredentials;
    	      this.connectionStatus = defaults.connectionStatus;
    	      this.connectionStrings = defaults.connectionStrings;
    	      this.connectorAgentId = defaults.connectorAgentId;
    	      this.connectorType = defaults.connectorType;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.externalDatabaseId = defaults.externalDatabaseId;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.state = defaults.state;
    	      this.timeConnectionStatusLastUpdated = defaults.timeConnectionStatusLastUpdated;
    	      this.timeCreated = defaults.timeCreated;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder connectionCredentials(List<GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionCredential> connectionCredentials) {
            this.connectionCredentials = Objects.requireNonNull(connectionCredentials);
            return this;
        }
        public Builder connectionCredentials(GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionCredential... connectionCredentials) {
            return connectionCredentials(List.of(connectionCredentials));
        }
        public Builder connectionStatus(String connectionStatus) {
            this.connectionStatus = Objects.requireNonNull(connectionStatus);
            return this;
        }
        public Builder connectionStrings(List<GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionString> connectionStrings) {
            this.connectionStrings = Objects.requireNonNull(connectionStrings);
            return this;
        }
        public Builder connectionStrings(GetExternalDatabaseConnectorsExternalDatabaseConnectorConnectionString... connectionStrings) {
            return connectionStrings(List.of(connectionStrings));
        }
        public Builder connectorAgentId(String connectorAgentId) {
            this.connectorAgentId = Objects.requireNonNull(connectorAgentId);
            return this;
        }
        public Builder connectorType(String connectorType) {
            this.connectorType = Objects.requireNonNull(connectorType);
            return this;
        }
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder externalDatabaseId(String externalDatabaseId) {
            this.externalDatabaseId = Objects.requireNonNull(externalDatabaseId);
            return this;
        }
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder timeConnectionStatusLastUpdated(String timeConnectionStatusLastUpdated) {
            this.timeConnectionStatusLastUpdated = Objects.requireNonNull(timeConnectionStatusLastUpdated);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }        public GetExternalDatabaseConnectorsExternalDatabaseConnector build() {
            return new GetExternalDatabaseConnectorsExternalDatabaseConnector(compartmentId, connectionCredentials, connectionStatus, connectionStrings, connectorAgentId, connectorType, definedTags, displayName, externalDatabaseId, freeformTags, id, lifecycleDetails, state, timeConnectionStatusLastUpdated, timeCreated);
        }
    }
}
