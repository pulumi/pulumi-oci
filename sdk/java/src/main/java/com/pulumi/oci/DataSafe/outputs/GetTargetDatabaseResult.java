// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.outputs.GetTargetDatabaseConnectionOption;
import com.pulumi.oci.DataSafe.outputs.GetTargetDatabaseCredential;
import com.pulumi.oci.DataSafe.outputs.GetTargetDatabaseDatabaseDetail;
import com.pulumi.oci.DataSafe.outputs.GetTargetDatabasePeerTargetDatabase;
import com.pulumi.oci.DataSafe.outputs.GetTargetDatabasePeerTargetDatabaseDetail;
import com.pulumi.oci.DataSafe.outputs.GetTargetDatabaseTlsConfig;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetTargetDatabaseResult {
    /**
     * @return The OCIDs of associated resources like database, Data Safe private endpoint etc.
     * 
     */
    private List<String> associatedResourceIds;
    /**
     * @return The OCID of the compartment which contains the Data Safe target database.
     * 
     */
    private String compartmentId;
    /**
     * @return Types of connection supported by Data Safe.
     * 
     */
    private List<GetTargetDatabaseConnectionOption> connectionOptions;
    /**
     * @return The database credentials required for Data Safe to connect to the database.
     * 
     */
    private List<GetTargetDatabaseCredential> credentials;
    /**
     * @return Details of the database for the registration in Data Safe.
     * 
     */
    private List<GetTargetDatabaseDatabaseDetail> databaseDetails;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return The description of the peer target database in Data Safe.
     * 
     */
    private String description;
    /**
     * @return The display name of the peer target database in Data Safe.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The OCID of the Data Safe target database.
     * 
     */
    private String id;
    /**
     * @return Details about the current state of the peer target database in Data Safe.
     * 
     */
    private String lifecycleDetails;
    private List<GetTargetDatabasePeerTargetDatabaseDetail> peerTargetDatabaseDetails;
    /**
     * @return The OCIDs of associated resources like Database, Data Safe private endpoint etc.
     * 
     */
    private List<GetTargetDatabasePeerTargetDatabase> peerTargetDatabases;
    /**
     * @return The current state of the target database in Data Safe.
     * 
     */
    private String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    private String targetDatabaseId;
    /**
     * @return The date and time the database was registered in Data Safe and created as a target database in Data Safe.
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time of the target database update in Data Safe.
     * 
     */
    private String timeUpdated;
    /**
     * @return The details required to establish a TLS enabled connection.
     * 
     */
    private List<GetTargetDatabaseTlsConfig> tlsConfigs;

    private GetTargetDatabaseResult() {}
    /**
     * @return The OCIDs of associated resources like database, Data Safe private endpoint etc.
     * 
     */
    public List<String> associatedResourceIds() {
        return this.associatedResourceIds;
    }
    /**
     * @return The OCID of the compartment which contains the Data Safe target database.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Types of connection supported by Data Safe.
     * 
     */
    public List<GetTargetDatabaseConnectionOption> connectionOptions() {
        return this.connectionOptions;
    }
    /**
     * @return The database credentials required for Data Safe to connect to the database.
     * 
     */
    public List<GetTargetDatabaseCredential> credentials() {
        return this.credentials;
    }
    /**
     * @return Details of the database for the registration in Data Safe.
     * 
     */
    public List<GetTargetDatabaseDatabaseDetail> databaseDetails() {
        return this.databaseDetails;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The description of the peer target database in Data Safe.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return The display name of the peer target database in Data Safe.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the Data Safe target database.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Details about the current state of the peer target database in Data Safe.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    public List<GetTargetDatabasePeerTargetDatabaseDetail> peerTargetDatabaseDetails() {
        return this.peerTargetDatabaseDetails;
    }
    /**
     * @return The OCIDs of associated resources like Database, Data Safe private endpoint etc.
     * 
     */
    public List<GetTargetDatabasePeerTargetDatabase> peerTargetDatabases() {
        return this.peerTargetDatabases;
    }
    /**
     * @return The current state of the target database in Data Safe.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    public String targetDatabaseId() {
        return this.targetDatabaseId;
    }
    /**
     * @return The date and time the database was registered in Data Safe and created as a target database in Data Safe.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time of the target database update in Data Safe.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return The details required to establish a TLS enabled connection.
     * 
     */
    public List<GetTargetDatabaseTlsConfig> tlsConfigs() {
        return this.tlsConfigs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetTargetDatabaseResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> associatedResourceIds;
        private String compartmentId;
        private List<GetTargetDatabaseConnectionOption> connectionOptions;
        private List<GetTargetDatabaseCredential> credentials;
        private List<GetTargetDatabaseDatabaseDetail> databaseDetails;
        private Map<String,String> definedTags;
        private String description;
        private String displayName;
        private Map<String,String> freeformTags;
        private String id;
        private String lifecycleDetails;
        private List<GetTargetDatabasePeerTargetDatabaseDetail> peerTargetDatabaseDetails;
        private List<GetTargetDatabasePeerTargetDatabase> peerTargetDatabases;
        private String state;
        private Map<String,String> systemTags;
        private String targetDatabaseId;
        private String timeCreated;
        private String timeUpdated;
        private List<GetTargetDatabaseTlsConfig> tlsConfigs;
        public Builder() {}
        public Builder(GetTargetDatabaseResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.associatedResourceIds = defaults.associatedResourceIds;
    	      this.compartmentId = defaults.compartmentId;
    	      this.connectionOptions = defaults.connectionOptions;
    	      this.credentials = defaults.credentials;
    	      this.databaseDetails = defaults.databaseDetails;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.peerTargetDatabaseDetails = defaults.peerTargetDatabaseDetails;
    	      this.peerTargetDatabases = defaults.peerTargetDatabases;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.targetDatabaseId = defaults.targetDatabaseId;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.tlsConfigs = defaults.tlsConfigs;
        }

        @CustomType.Setter
        public Builder associatedResourceIds(List<String> associatedResourceIds) {
            if (associatedResourceIds == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabaseResult", "associatedResourceIds");
            }
            this.associatedResourceIds = associatedResourceIds;
            return this;
        }
        public Builder associatedResourceIds(String... associatedResourceIds) {
            return associatedResourceIds(List.of(associatedResourceIds));
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabaseResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder connectionOptions(List<GetTargetDatabaseConnectionOption> connectionOptions) {
            if (connectionOptions == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabaseResult", "connectionOptions");
            }
            this.connectionOptions = connectionOptions;
            return this;
        }
        public Builder connectionOptions(GetTargetDatabaseConnectionOption... connectionOptions) {
            return connectionOptions(List.of(connectionOptions));
        }
        @CustomType.Setter
        public Builder credentials(List<GetTargetDatabaseCredential> credentials) {
            if (credentials == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabaseResult", "credentials");
            }
            this.credentials = credentials;
            return this;
        }
        public Builder credentials(GetTargetDatabaseCredential... credentials) {
            return credentials(List.of(credentials));
        }
        @CustomType.Setter
        public Builder databaseDetails(List<GetTargetDatabaseDatabaseDetail> databaseDetails) {
            if (databaseDetails == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabaseResult", "databaseDetails");
            }
            this.databaseDetails = databaseDetails;
            return this;
        }
        public Builder databaseDetails(GetTargetDatabaseDatabaseDetail... databaseDetails) {
            return databaseDetails(List.of(databaseDetails));
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabaseResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabaseResult", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabaseResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabaseResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabaseResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabaseResult", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder peerTargetDatabaseDetails(List<GetTargetDatabasePeerTargetDatabaseDetail> peerTargetDatabaseDetails) {
            if (peerTargetDatabaseDetails == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabaseResult", "peerTargetDatabaseDetails");
            }
            this.peerTargetDatabaseDetails = peerTargetDatabaseDetails;
            return this;
        }
        public Builder peerTargetDatabaseDetails(GetTargetDatabasePeerTargetDatabaseDetail... peerTargetDatabaseDetails) {
            return peerTargetDatabaseDetails(List.of(peerTargetDatabaseDetails));
        }
        @CustomType.Setter
        public Builder peerTargetDatabases(List<GetTargetDatabasePeerTargetDatabase> peerTargetDatabases) {
            if (peerTargetDatabases == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabaseResult", "peerTargetDatabases");
            }
            this.peerTargetDatabases = peerTargetDatabases;
            return this;
        }
        public Builder peerTargetDatabases(GetTargetDatabasePeerTargetDatabase... peerTargetDatabases) {
            return peerTargetDatabases(List.of(peerTargetDatabases));
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabaseResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabaseResult", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder targetDatabaseId(String targetDatabaseId) {
            if (targetDatabaseId == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabaseResult", "targetDatabaseId");
            }
            this.targetDatabaseId = targetDatabaseId;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabaseResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabaseResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder tlsConfigs(List<GetTargetDatabaseTlsConfig> tlsConfigs) {
            if (tlsConfigs == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabaseResult", "tlsConfigs");
            }
            this.tlsConfigs = tlsConfigs;
            return this;
        }
        public Builder tlsConfigs(GetTargetDatabaseTlsConfig... tlsConfigs) {
            return tlsConfigs(List.of(tlsConfigs));
        }
        public GetTargetDatabaseResult build() {
            final var _resultValue = new GetTargetDatabaseResult();
            _resultValue.associatedResourceIds = associatedResourceIds;
            _resultValue.compartmentId = compartmentId;
            _resultValue.connectionOptions = connectionOptions;
            _resultValue.credentials = credentials;
            _resultValue.databaseDetails = databaseDetails;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.peerTargetDatabaseDetails = peerTargetDatabaseDetails;
            _resultValue.peerTargetDatabases = peerTargetDatabases;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.targetDatabaseId = targetDatabaseId;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            _resultValue.tlsConfigs = tlsConfigs;
            return _resultValue;
        }
    }
}
