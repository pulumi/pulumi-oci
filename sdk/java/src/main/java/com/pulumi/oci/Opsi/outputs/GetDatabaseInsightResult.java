// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Opsi.outputs.GetDatabaseInsightConnectionCredentialDetail;
import com.pulumi.oci.Opsi.outputs.GetDatabaseInsightConnectionDetail;
import com.pulumi.oci.Opsi.outputs.GetDatabaseInsightCredentialDetail;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetDatabaseInsightResult {
    /**
     * @return Compartment identifier of the database
     * 
     */
    private String compartmentId;
    /**
     * @return User credential details to connect to the database.
     * 
     */
    private List<GetDatabaseInsightConnectionCredentialDetail> connectionCredentialDetails;
    /**
     * @return Connection details to connect to the database. HostName, protocol, and port should be specified.
     * 
     */
    private List<GetDatabaseInsightConnectionDetail> connectionDetails;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of External Database Connector
     * 
     */
    private String connectorId;
    /**
     * @return User credential details to connect to the database.
     * 
     */
    private List<GetDatabaseInsightCredentialDetail> credentialDetails;
    /**
     * @return A message describing the status of the database connection of this resource. For example, it can be used to provide actionable information about the permission and content validity of the database connection.
     * 
     */
    private String databaseConnectionStatusDetails;
    /**
     * @return (Required when entity_source=EXTERNAL_MYSQL_DATABASE_SYSTEM) (Updatable) The DBM owned database connector [OCID](https://www.terraform.io/iaas/database-management/doc/view-connector-details.html) mapping to the database credentials and connection details.
     * 
     */
    private String databaseConnectorId;
    /**
     * @return Display name of database
     * 
     */
    private String databaseDisplayName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
     * 
     */
    private String databaseId;
    private String databaseInsightId;
    /**
     * @return Name of database
     * 
     */
    private String databaseName;
    /**
     * @return Oracle Cloud Infrastructure database resource type
     * 
     */
    private String databaseResourceType;
    /**
     * @return Ops Insights internal representation of the database type.
     * 
     */
    private String databaseType;
    /**
     * @return The version of the database.
     * 
     */
    private String databaseVersion;
    private String dbmPrivateEndpointId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    private String deploymentType;
    /**
     * @return OPSI Enterprise Manager Bridge OCID
     * 
     */
    private String enterpriseManagerBridgeId;
    /**
     * @return Enterprise Manager Entity Display Name
     * 
     */
    private String enterpriseManagerEntityDisplayName;
    /**
     * @return Enterprise Manager Entity Unique Identifier
     * 
     */
    private String enterpriseManagerEntityIdentifier;
    /**
     * @return Enterprise Manager Entity Name
     * 
     */
    private String enterpriseManagerEntityName;
    /**
     * @return Enterprise Manager Entity Type
     * 
     */
    private String enterpriseManagerEntityType;
    /**
     * @return Enterprise Manager Unqiue Identifier
     * 
     */
    private String enterpriseManagerIdentifier;
    /**
     * @return Source of the database entity.
     * 
     */
    private String entitySource;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata insight.
     * 
     */
    private String exadataInsightId;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return Database insight identifier
     * 
     */
    private String id;
    /**
     * @return Flag is to identify if advanced features for autonomous database is enabled or not
     * 
     */
    private Boolean isAdvancedFeaturesEnabled;
    /**
     * @return Specifies if MYSQL DB System has heatwave cluster attached.
     * 
     */
    private Boolean isHeatWaveClusterAttached;
    /**
     * @return Specifies if MYSQL DB System is highly available.
     * 
     */
    private Boolean isHighlyAvailable;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    private String lifecycleDetails;
    private String managementAgentId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the OPSI private endpoint
     * 
     */
    private String opsiPrivateEndpointId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM Cluster or DB System ID, depending on which configuration the resource belongs to.
     * 
     */
    private String parentId;
    /**
     * @return Processor count. This is the OCPU count for Autonomous Database and CPU core count for other database types.
     * 
     */
    private Integer processorCount;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata Infrastructure.
     * 
     */
    private String rootId;
    /**
     * @return Database service name used for connection requests.
     * 
     */
    private String serviceName;
    /**
     * @return The current state of the database.
     * 
     */
    private String state;
    /**
     * @return Indicates the status of a database insight in Operations Insights
     * 
     */
    private String status;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The time the the database insight was first enabled. An RFC3339 formatted datetime string
     * 
     */
    private String timeCreated;
    /**
     * @return The time the database insight was updated. An RFC3339 formatted datetime string
     * 
     */
    private String timeUpdated;

    private GetDatabaseInsightResult() {}
    /**
     * @return Compartment identifier of the database
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return User credential details to connect to the database.
     * 
     */
    public List<GetDatabaseInsightConnectionCredentialDetail> connectionCredentialDetails() {
        return this.connectionCredentialDetails;
    }
    /**
     * @return Connection details to connect to the database. HostName, protocol, and port should be specified.
     * 
     */
    public List<GetDatabaseInsightConnectionDetail> connectionDetails() {
        return this.connectionDetails;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of External Database Connector
     * 
     */
    public String connectorId() {
        return this.connectorId;
    }
    /**
     * @return User credential details to connect to the database.
     * 
     */
    public List<GetDatabaseInsightCredentialDetail> credentialDetails() {
        return this.credentialDetails;
    }
    /**
     * @return A message describing the status of the database connection of this resource. For example, it can be used to provide actionable information about the permission and content validity of the database connection.
     * 
     */
    public String databaseConnectionStatusDetails() {
        return this.databaseConnectionStatusDetails;
    }
    /**
     * @return (Required when entity_source=EXTERNAL_MYSQL_DATABASE_SYSTEM) (Updatable) The DBM owned database connector [OCID](https://www.terraform.io/iaas/database-management/doc/view-connector-details.html) mapping to the database credentials and connection details.
     * 
     */
    public String databaseConnectorId() {
        return this.databaseConnectorId;
    }
    /**
     * @return Display name of database
     * 
     */
    public String databaseDisplayName() {
        return this.databaseDisplayName;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
     * 
     */
    public String databaseId() {
        return this.databaseId;
    }
    public String databaseInsightId() {
        return this.databaseInsightId;
    }
    /**
     * @return Name of database
     * 
     */
    public String databaseName() {
        return this.databaseName;
    }
    /**
     * @return Oracle Cloud Infrastructure database resource type
     * 
     */
    public String databaseResourceType() {
        return this.databaseResourceType;
    }
    /**
     * @return Ops Insights internal representation of the database type.
     * 
     */
    public String databaseType() {
        return this.databaseType;
    }
    /**
     * @return The version of the database.
     * 
     */
    public String databaseVersion() {
        return this.databaseVersion;
    }
    public String dbmPrivateEndpointId() {
        return this.dbmPrivateEndpointId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    public String deploymentType() {
        return this.deploymentType;
    }
    /**
     * @return OPSI Enterprise Manager Bridge OCID
     * 
     */
    public String enterpriseManagerBridgeId() {
        return this.enterpriseManagerBridgeId;
    }
    /**
     * @return Enterprise Manager Entity Display Name
     * 
     */
    public String enterpriseManagerEntityDisplayName() {
        return this.enterpriseManagerEntityDisplayName;
    }
    /**
     * @return Enterprise Manager Entity Unique Identifier
     * 
     */
    public String enterpriseManagerEntityIdentifier() {
        return this.enterpriseManagerEntityIdentifier;
    }
    /**
     * @return Enterprise Manager Entity Name
     * 
     */
    public String enterpriseManagerEntityName() {
        return this.enterpriseManagerEntityName;
    }
    /**
     * @return Enterprise Manager Entity Type
     * 
     */
    public String enterpriseManagerEntityType() {
        return this.enterpriseManagerEntityType;
    }
    /**
     * @return Enterprise Manager Unqiue Identifier
     * 
     */
    public String enterpriseManagerIdentifier() {
        return this.enterpriseManagerIdentifier;
    }
    /**
     * @return Source of the database entity.
     * 
     */
    public String entitySource() {
        return this.entitySource;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata insight.
     * 
     */
    public String exadataInsightId() {
        return this.exadataInsightId;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return Database insight identifier
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Flag is to identify if advanced features for autonomous database is enabled or not
     * 
     */
    public Boolean isAdvancedFeaturesEnabled() {
        return this.isAdvancedFeaturesEnabled;
    }
    /**
     * @return Specifies if MYSQL DB System has heatwave cluster attached.
     * 
     */
    public Boolean isHeatWaveClusterAttached() {
        return this.isHeatWaveClusterAttached;
    }
    /**
     * @return Specifies if MYSQL DB System is highly available.
     * 
     */
    public Boolean isHighlyAvailable() {
        return this.isHighlyAvailable;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    public String managementAgentId() {
        return this.managementAgentId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the OPSI private endpoint
     * 
     */
    public String opsiPrivateEndpointId() {
        return this.opsiPrivateEndpointId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM Cluster or DB System ID, depending on which configuration the resource belongs to.
     * 
     */
    public String parentId() {
        return this.parentId;
    }
    /**
     * @return Processor count. This is the OCPU count for Autonomous Database and CPU core count for other database types.
     * 
     */
    public Integer processorCount() {
        return this.processorCount;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata Infrastructure.
     * 
     */
    public String rootId() {
        return this.rootId;
    }
    /**
     * @return Database service name used for connection requests.
     * 
     */
    public String serviceName() {
        return this.serviceName;
    }
    /**
     * @return The current state of the database.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Indicates the status of a database insight in Operations Insights
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The time the the database insight was first enabled. An RFC3339 formatted datetime string
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the database insight was updated. An RFC3339 formatted datetime string
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDatabaseInsightResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private List<GetDatabaseInsightConnectionCredentialDetail> connectionCredentialDetails;
        private List<GetDatabaseInsightConnectionDetail> connectionDetails;
        private String connectorId;
        private List<GetDatabaseInsightCredentialDetail> credentialDetails;
        private String databaseConnectionStatusDetails;
        private String databaseConnectorId;
        private String databaseDisplayName;
        private String databaseId;
        private String databaseInsightId;
        private String databaseName;
        private String databaseResourceType;
        private String databaseType;
        private String databaseVersion;
        private String dbmPrivateEndpointId;
        private Map<String,String> definedTags;
        private String deploymentType;
        private String enterpriseManagerBridgeId;
        private String enterpriseManagerEntityDisplayName;
        private String enterpriseManagerEntityIdentifier;
        private String enterpriseManagerEntityName;
        private String enterpriseManagerEntityType;
        private String enterpriseManagerIdentifier;
        private String entitySource;
        private String exadataInsightId;
        private Map<String,String> freeformTags;
        private String id;
        private Boolean isAdvancedFeaturesEnabled;
        private Boolean isHeatWaveClusterAttached;
        private Boolean isHighlyAvailable;
        private String lifecycleDetails;
        private String managementAgentId;
        private String opsiPrivateEndpointId;
        private String parentId;
        private Integer processorCount;
        private String rootId;
        private String serviceName;
        private String state;
        private String status;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetDatabaseInsightResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.connectionCredentialDetails = defaults.connectionCredentialDetails;
    	      this.connectionDetails = defaults.connectionDetails;
    	      this.connectorId = defaults.connectorId;
    	      this.credentialDetails = defaults.credentialDetails;
    	      this.databaseConnectionStatusDetails = defaults.databaseConnectionStatusDetails;
    	      this.databaseConnectorId = defaults.databaseConnectorId;
    	      this.databaseDisplayName = defaults.databaseDisplayName;
    	      this.databaseId = defaults.databaseId;
    	      this.databaseInsightId = defaults.databaseInsightId;
    	      this.databaseName = defaults.databaseName;
    	      this.databaseResourceType = defaults.databaseResourceType;
    	      this.databaseType = defaults.databaseType;
    	      this.databaseVersion = defaults.databaseVersion;
    	      this.dbmPrivateEndpointId = defaults.dbmPrivateEndpointId;
    	      this.definedTags = defaults.definedTags;
    	      this.deploymentType = defaults.deploymentType;
    	      this.enterpriseManagerBridgeId = defaults.enterpriseManagerBridgeId;
    	      this.enterpriseManagerEntityDisplayName = defaults.enterpriseManagerEntityDisplayName;
    	      this.enterpriseManagerEntityIdentifier = defaults.enterpriseManagerEntityIdentifier;
    	      this.enterpriseManagerEntityName = defaults.enterpriseManagerEntityName;
    	      this.enterpriseManagerEntityType = defaults.enterpriseManagerEntityType;
    	      this.enterpriseManagerIdentifier = defaults.enterpriseManagerIdentifier;
    	      this.entitySource = defaults.entitySource;
    	      this.exadataInsightId = defaults.exadataInsightId;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isAdvancedFeaturesEnabled = defaults.isAdvancedFeaturesEnabled;
    	      this.isHeatWaveClusterAttached = defaults.isHeatWaveClusterAttached;
    	      this.isHighlyAvailable = defaults.isHighlyAvailable;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.managementAgentId = defaults.managementAgentId;
    	      this.opsiPrivateEndpointId = defaults.opsiPrivateEndpointId;
    	      this.parentId = defaults.parentId;
    	      this.processorCount = defaults.processorCount;
    	      this.rootId = defaults.rootId;
    	      this.serviceName = defaults.serviceName;
    	      this.state = defaults.state;
    	      this.status = defaults.status;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder connectionCredentialDetails(List<GetDatabaseInsightConnectionCredentialDetail> connectionCredentialDetails) {
            if (connectionCredentialDetails == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "connectionCredentialDetails");
            }
            this.connectionCredentialDetails = connectionCredentialDetails;
            return this;
        }
        public Builder connectionCredentialDetails(GetDatabaseInsightConnectionCredentialDetail... connectionCredentialDetails) {
            return connectionCredentialDetails(List.of(connectionCredentialDetails));
        }
        @CustomType.Setter
        public Builder connectionDetails(List<GetDatabaseInsightConnectionDetail> connectionDetails) {
            if (connectionDetails == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "connectionDetails");
            }
            this.connectionDetails = connectionDetails;
            return this;
        }
        public Builder connectionDetails(GetDatabaseInsightConnectionDetail... connectionDetails) {
            return connectionDetails(List.of(connectionDetails));
        }
        @CustomType.Setter
        public Builder connectorId(String connectorId) {
            if (connectorId == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "connectorId");
            }
            this.connectorId = connectorId;
            return this;
        }
        @CustomType.Setter
        public Builder credentialDetails(List<GetDatabaseInsightCredentialDetail> credentialDetails) {
            if (credentialDetails == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "credentialDetails");
            }
            this.credentialDetails = credentialDetails;
            return this;
        }
        public Builder credentialDetails(GetDatabaseInsightCredentialDetail... credentialDetails) {
            return credentialDetails(List.of(credentialDetails));
        }
        @CustomType.Setter
        public Builder databaseConnectionStatusDetails(String databaseConnectionStatusDetails) {
            if (databaseConnectionStatusDetails == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "databaseConnectionStatusDetails");
            }
            this.databaseConnectionStatusDetails = databaseConnectionStatusDetails;
            return this;
        }
        @CustomType.Setter
        public Builder databaseConnectorId(String databaseConnectorId) {
            if (databaseConnectorId == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "databaseConnectorId");
            }
            this.databaseConnectorId = databaseConnectorId;
            return this;
        }
        @CustomType.Setter
        public Builder databaseDisplayName(String databaseDisplayName) {
            if (databaseDisplayName == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "databaseDisplayName");
            }
            this.databaseDisplayName = databaseDisplayName;
            return this;
        }
        @CustomType.Setter
        public Builder databaseId(String databaseId) {
            if (databaseId == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "databaseId");
            }
            this.databaseId = databaseId;
            return this;
        }
        @CustomType.Setter
        public Builder databaseInsightId(String databaseInsightId) {
            if (databaseInsightId == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "databaseInsightId");
            }
            this.databaseInsightId = databaseInsightId;
            return this;
        }
        @CustomType.Setter
        public Builder databaseName(String databaseName) {
            if (databaseName == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "databaseName");
            }
            this.databaseName = databaseName;
            return this;
        }
        @CustomType.Setter
        public Builder databaseResourceType(String databaseResourceType) {
            if (databaseResourceType == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "databaseResourceType");
            }
            this.databaseResourceType = databaseResourceType;
            return this;
        }
        @CustomType.Setter
        public Builder databaseType(String databaseType) {
            if (databaseType == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "databaseType");
            }
            this.databaseType = databaseType;
            return this;
        }
        @CustomType.Setter
        public Builder databaseVersion(String databaseVersion) {
            if (databaseVersion == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "databaseVersion");
            }
            this.databaseVersion = databaseVersion;
            return this;
        }
        @CustomType.Setter
        public Builder dbmPrivateEndpointId(String dbmPrivateEndpointId) {
            if (dbmPrivateEndpointId == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "dbmPrivateEndpointId");
            }
            this.dbmPrivateEndpointId = dbmPrivateEndpointId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder deploymentType(String deploymentType) {
            if (deploymentType == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "deploymentType");
            }
            this.deploymentType = deploymentType;
            return this;
        }
        @CustomType.Setter
        public Builder enterpriseManagerBridgeId(String enterpriseManagerBridgeId) {
            if (enterpriseManagerBridgeId == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "enterpriseManagerBridgeId");
            }
            this.enterpriseManagerBridgeId = enterpriseManagerBridgeId;
            return this;
        }
        @CustomType.Setter
        public Builder enterpriseManagerEntityDisplayName(String enterpriseManagerEntityDisplayName) {
            if (enterpriseManagerEntityDisplayName == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "enterpriseManagerEntityDisplayName");
            }
            this.enterpriseManagerEntityDisplayName = enterpriseManagerEntityDisplayName;
            return this;
        }
        @CustomType.Setter
        public Builder enterpriseManagerEntityIdentifier(String enterpriseManagerEntityIdentifier) {
            if (enterpriseManagerEntityIdentifier == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "enterpriseManagerEntityIdentifier");
            }
            this.enterpriseManagerEntityIdentifier = enterpriseManagerEntityIdentifier;
            return this;
        }
        @CustomType.Setter
        public Builder enterpriseManagerEntityName(String enterpriseManagerEntityName) {
            if (enterpriseManagerEntityName == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "enterpriseManagerEntityName");
            }
            this.enterpriseManagerEntityName = enterpriseManagerEntityName;
            return this;
        }
        @CustomType.Setter
        public Builder enterpriseManagerEntityType(String enterpriseManagerEntityType) {
            if (enterpriseManagerEntityType == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "enterpriseManagerEntityType");
            }
            this.enterpriseManagerEntityType = enterpriseManagerEntityType;
            return this;
        }
        @CustomType.Setter
        public Builder enterpriseManagerIdentifier(String enterpriseManagerIdentifier) {
            if (enterpriseManagerIdentifier == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "enterpriseManagerIdentifier");
            }
            this.enterpriseManagerIdentifier = enterpriseManagerIdentifier;
            return this;
        }
        @CustomType.Setter
        public Builder entitySource(String entitySource) {
            if (entitySource == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "entitySource");
            }
            this.entitySource = entitySource;
            return this;
        }
        @CustomType.Setter
        public Builder exadataInsightId(String exadataInsightId) {
            if (exadataInsightId == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "exadataInsightId");
            }
            this.exadataInsightId = exadataInsightId;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isAdvancedFeaturesEnabled(Boolean isAdvancedFeaturesEnabled) {
            if (isAdvancedFeaturesEnabled == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "isAdvancedFeaturesEnabled");
            }
            this.isAdvancedFeaturesEnabled = isAdvancedFeaturesEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder isHeatWaveClusterAttached(Boolean isHeatWaveClusterAttached) {
            if (isHeatWaveClusterAttached == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "isHeatWaveClusterAttached");
            }
            this.isHeatWaveClusterAttached = isHeatWaveClusterAttached;
            return this;
        }
        @CustomType.Setter
        public Builder isHighlyAvailable(Boolean isHighlyAvailable) {
            if (isHighlyAvailable == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "isHighlyAvailable");
            }
            this.isHighlyAvailable = isHighlyAvailable;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder managementAgentId(String managementAgentId) {
            if (managementAgentId == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "managementAgentId");
            }
            this.managementAgentId = managementAgentId;
            return this;
        }
        @CustomType.Setter
        public Builder opsiPrivateEndpointId(String opsiPrivateEndpointId) {
            if (opsiPrivateEndpointId == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "opsiPrivateEndpointId");
            }
            this.opsiPrivateEndpointId = opsiPrivateEndpointId;
            return this;
        }
        @CustomType.Setter
        public Builder parentId(String parentId) {
            if (parentId == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "parentId");
            }
            this.parentId = parentId;
            return this;
        }
        @CustomType.Setter
        public Builder processorCount(Integer processorCount) {
            if (processorCount == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "processorCount");
            }
            this.processorCount = processorCount;
            return this;
        }
        @CustomType.Setter
        public Builder rootId(String rootId) {
            if (rootId == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "rootId");
            }
            this.rootId = rootId;
            return this;
        }
        @CustomType.Setter
        public Builder serviceName(String serviceName) {
            if (serviceName == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "serviceName");
            }
            this.serviceName = serviceName;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            if (status == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "status");
            }
            this.status = status;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetDatabaseInsightResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetDatabaseInsightResult build() {
            final var _resultValue = new GetDatabaseInsightResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.connectionCredentialDetails = connectionCredentialDetails;
            _resultValue.connectionDetails = connectionDetails;
            _resultValue.connectorId = connectorId;
            _resultValue.credentialDetails = credentialDetails;
            _resultValue.databaseConnectionStatusDetails = databaseConnectionStatusDetails;
            _resultValue.databaseConnectorId = databaseConnectorId;
            _resultValue.databaseDisplayName = databaseDisplayName;
            _resultValue.databaseId = databaseId;
            _resultValue.databaseInsightId = databaseInsightId;
            _resultValue.databaseName = databaseName;
            _resultValue.databaseResourceType = databaseResourceType;
            _resultValue.databaseType = databaseType;
            _resultValue.databaseVersion = databaseVersion;
            _resultValue.dbmPrivateEndpointId = dbmPrivateEndpointId;
            _resultValue.definedTags = definedTags;
            _resultValue.deploymentType = deploymentType;
            _resultValue.enterpriseManagerBridgeId = enterpriseManagerBridgeId;
            _resultValue.enterpriseManagerEntityDisplayName = enterpriseManagerEntityDisplayName;
            _resultValue.enterpriseManagerEntityIdentifier = enterpriseManagerEntityIdentifier;
            _resultValue.enterpriseManagerEntityName = enterpriseManagerEntityName;
            _resultValue.enterpriseManagerEntityType = enterpriseManagerEntityType;
            _resultValue.enterpriseManagerIdentifier = enterpriseManagerIdentifier;
            _resultValue.entitySource = entitySource;
            _resultValue.exadataInsightId = exadataInsightId;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.isAdvancedFeaturesEnabled = isAdvancedFeaturesEnabled;
            _resultValue.isHeatWaveClusterAttached = isHeatWaveClusterAttached;
            _resultValue.isHighlyAvailable = isHighlyAvailable;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.managementAgentId = managementAgentId;
            _resultValue.opsiPrivateEndpointId = opsiPrivateEndpointId;
            _resultValue.parentId = parentId;
            _resultValue.processorCount = processorCount;
            _resultValue.rootId = rootId;
            _resultValue.serviceName = serviceName;
            _resultValue.state = state;
            _resultValue.status = status;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
