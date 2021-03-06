// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDataGuardAssociationsDataGuardAssociation {
    /**
     * @return The lag time between updates to the primary database and application of the redo data on the standby database, as computed by the reporting database.  Example: `9 seconds`
     * 
     */
    private final String applyLag;
    /**
     * @return The rate at which redo logs are synced between the associated databases.  Example: `180 Mb per second`
     * 
     */
    private final String applyRate;
    private final String availabilityDomain;
    private final List<String> backupNetworkNsgIds;
    private final Boolean createAsync;
    private final String creationType;
    private final String databaseAdminPassword;
    /**
     * @return The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    private final String databaseId;
    private final String databaseSoftwareImageId;
    private final String deleteStandbyDbHomeOnDelete;
    private final String displayName;
    private final String hostname;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Data Guard association.
     * 
     */
    private final String id;
    /**
     * @return True if active Data Guard is enabled.
     * 
     */
    private final Boolean isActiveDataGuardEnabled;
    /**
     * @return Additional information about the current lifecycleState, if available.
     * 
     */
    private final String lifecycleDetails;
    private final List<String> nsgIds;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer database&#39;s Data Guard association.
     * 
     */
    private final String peerDataGuardAssociationId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated peer database.
     * 
     */
    private final String peerDatabaseId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home containing the associated peer database.
     * 
     */
    private final String peerDbHomeId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system containing the associated peer database.
     * 
     */
    private final String peerDbSystemId;
    private final String peerDbUniqueName;
    /**
     * @return The role of the peer database in this Data Guard association.
     * 
     */
    private final String peerRole;
    private final String peerSidPrefix;
    private final String peerVmClusterId;
    /**
     * @return The protection mode of this Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
     * 
     */
    private final String protectionMode;
    /**
     * @return The role of the reporting database in this Data Guard association.
     * 
     */
    private final String role;
    private final String shape;
    /**
     * @return The current state of the Data Guard association.
     * 
     */
    private final String state;
    private final String subnetId;
    /**
     * @return The date and time the Data Guard association was created.
     * 
     */
    private final String timeCreated;
    /**
     * @return The redo transport type used by this Data Guard association.  For more information, see [Redo Transport Services](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-redo-transport-services.htm#SBYDB00400) in the Oracle Data Guard documentation.
     * 
     */
    private final String transportType;

    @CustomType.Constructor
    private GetDataGuardAssociationsDataGuardAssociation(
        @CustomType.Parameter("applyLag") String applyLag,
        @CustomType.Parameter("applyRate") String applyRate,
        @CustomType.Parameter("availabilityDomain") String availabilityDomain,
        @CustomType.Parameter("backupNetworkNsgIds") List<String> backupNetworkNsgIds,
        @CustomType.Parameter("createAsync") Boolean createAsync,
        @CustomType.Parameter("creationType") String creationType,
        @CustomType.Parameter("databaseAdminPassword") String databaseAdminPassword,
        @CustomType.Parameter("databaseId") String databaseId,
        @CustomType.Parameter("databaseSoftwareImageId") String databaseSoftwareImageId,
        @CustomType.Parameter("deleteStandbyDbHomeOnDelete") String deleteStandbyDbHomeOnDelete,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("hostname") String hostname,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("isActiveDataGuardEnabled") Boolean isActiveDataGuardEnabled,
        @CustomType.Parameter("lifecycleDetails") String lifecycleDetails,
        @CustomType.Parameter("nsgIds") List<String> nsgIds,
        @CustomType.Parameter("peerDataGuardAssociationId") String peerDataGuardAssociationId,
        @CustomType.Parameter("peerDatabaseId") String peerDatabaseId,
        @CustomType.Parameter("peerDbHomeId") String peerDbHomeId,
        @CustomType.Parameter("peerDbSystemId") String peerDbSystemId,
        @CustomType.Parameter("peerDbUniqueName") String peerDbUniqueName,
        @CustomType.Parameter("peerRole") String peerRole,
        @CustomType.Parameter("peerSidPrefix") String peerSidPrefix,
        @CustomType.Parameter("peerVmClusterId") String peerVmClusterId,
        @CustomType.Parameter("protectionMode") String protectionMode,
        @CustomType.Parameter("role") String role,
        @CustomType.Parameter("shape") String shape,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("subnetId") String subnetId,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("transportType") String transportType) {
        this.applyLag = applyLag;
        this.applyRate = applyRate;
        this.availabilityDomain = availabilityDomain;
        this.backupNetworkNsgIds = backupNetworkNsgIds;
        this.createAsync = createAsync;
        this.creationType = creationType;
        this.databaseAdminPassword = databaseAdminPassword;
        this.databaseId = databaseId;
        this.databaseSoftwareImageId = databaseSoftwareImageId;
        this.deleteStandbyDbHomeOnDelete = deleteStandbyDbHomeOnDelete;
        this.displayName = displayName;
        this.hostname = hostname;
        this.id = id;
        this.isActiveDataGuardEnabled = isActiveDataGuardEnabled;
        this.lifecycleDetails = lifecycleDetails;
        this.nsgIds = nsgIds;
        this.peerDataGuardAssociationId = peerDataGuardAssociationId;
        this.peerDatabaseId = peerDatabaseId;
        this.peerDbHomeId = peerDbHomeId;
        this.peerDbSystemId = peerDbSystemId;
        this.peerDbUniqueName = peerDbUniqueName;
        this.peerRole = peerRole;
        this.peerSidPrefix = peerSidPrefix;
        this.peerVmClusterId = peerVmClusterId;
        this.protectionMode = protectionMode;
        this.role = role;
        this.shape = shape;
        this.state = state;
        this.subnetId = subnetId;
        this.timeCreated = timeCreated;
        this.transportType = transportType;
    }

    /**
     * @return The lag time between updates to the primary database and application of the redo data on the standby database, as computed by the reporting database.  Example: `9 seconds`
     * 
     */
    public String applyLag() {
        return this.applyLag;
    }
    /**
     * @return The rate at which redo logs are synced between the associated databases.  Example: `180 Mb per second`
     * 
     */
    public String applyRate() {
        return this.applyRate;
    }
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    public List<String> backupNetworkNsgIds() {
        return this.backupNetworkNsgIds;
    }
    public Boolean createAsync() {
        return this.createAsync;
    }
    public String creationType() {
        return this.creationType;
    }
    public String databaseAdminPassword() {
        return this.databaseAdminPassword;
    }
    /**
     * @return The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String databaseId() {
        return this.databaseId;
    }
    public String databaseSoftwareImageId() {
        return this.databaseSoftwareImageId;
    }
    public String deleteStandbyDbHomeOnDelete() {
        return this.deleteStandbyDbHomeOnDelete;
    }
    public String displayName() {
        return this.displayName;
    }
    public String hostname() {
        return this.hostname;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Data Guard association.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return True if active Data Guard is enabled.
     * 
     */
    public Boolean isActiveDataGuardEnabled() {
        return this.isActiveDataGuardEnabled;
    }
    /**
     * @return Additional information about the current lifecycleState, if available.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    public List<String> nsgIds() {
        return this.nsgIds;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer database&#39;s Data Guard association.
     * 
     */
    public String peerDataGuardAssociationId() {
        return this.peerDataGuardAssociationId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated peer database.
     * 
     */
    public String peerDatabaseId() {
        return this.peerDatabaseId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home containing the associated peer database.
     * 
     */
    public String peerDbHomeId() {
        return this.peerDbHomeId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system containing the associated peer database.
     * 
     */
    public String peerDbSystemId() {
        return this.peerDbSystemId;
    }
    public String peerDbUniqueName() {
        return this.peerDbUniqueName;
    }
    /**
     * @return The role of the peer database in this Data Guard association.
     * 
     */
    public String peerRole() {
        return this.peerRole;
    }
    public String peerSidPrefix() {
        return this.peerSidPrefix;
    }
    public String peerVmClusterId() {
        return this.peerVmClusterId;
    }
    /**
     * @return The protection mode of this Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
     * 
     */
    public String protectionMode() {
        return this.protectionMode;
    }
    /**
     * @return The role of the reporting database in this Data Guard association.
     * 
     */
    public String role() {
        return this.role;
    }
    public String shape() {
        return this.shape;
    }
    /**
     * @return The current state of the Data Guard association.
     * 
     */
    public String state() {
        return this.state;
    }
    public String subnetId() {
        return this.subnetId;
    }
    /**
     * @return The date and time the Data Guard association was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The redo transport type used by this Data Guard association.  For more information, see [Redo Transport Services](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-redo-transport-services.htm#SBYDB00400) in the Oracle Data Guard documentation.
     * 
     */
    public String transportType() {
        return this.transportType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDataGuardAssociationsDataGuardAssociation defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String applyLag;
        private String applyRate;
        private String availabilityDomain;
        private List<String> backupNetworkNsgIds;
        private Boolean createAsync;
        private String creationType;
        private String databaseAdminPassword;
        private String databaseId;
        private String databaseSoftwareImageId;
        private String deleteStandbyDbHomeOnDelete;
        private String displayName;
        private String hostname;
        private String id;
        private Boolean isActiveDataGuardEnabled;
        private String lifecycleDetails;
        private List<String> nsgIds;
        private String peerDataGuardAssociationId;
        private String peerDatabaseId;
        private String peerDbHomeId;
        private String peerDbSystemId;
        private String peerDbUniqueName;
        private String peerRole;
        private String peerSidPrefix;
        private String peerVmClusterId;
        private String protectionMode;
        private String role;
        private String shape;
        private String state;
        private String subnetId;
        private String timeCreated;
        private String transportType;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDataGuardAssociationsDataGuardAssociation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applyLag = defaults.applyLag;
    	      this.applyRate = defaults.applyRate;
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.backupNetworkNsgIds = defaults.backupNetworkNsgIds;
    	      this.createAsync = defaults.createAsync;
    	      this.creationType = defaults.creationType;
    	      this.databaseAdminPassword = defaults.databaseAdminPassword;
    	      this.databaseId = defaults.databaseId;
    	      this.databaseSoftwareImageId = defaults.databaseSoftwareImageId;
    	      this.deleteStandbyDbHomeOnDelete = defaults.deleteStandbyDbHomeOnDelete;
    	      this.displayName = defaults.displayName;
    	      this.hostname = defaults.hostname;
    	      this.id = defaults.id;
    	      this.isActiveDataGuardEnabled = defaults.isActiveDataGuardEnabled;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.nsgIds = defaults.nsgIds;
    	      this.peerDataGuardAssociationId = defaults.peerDataGuardAssociationId;
    	      this.peerDatabaseId = defaults.peerDatabaseId;
    	      this.peerDbHomeId = defaults.peerDbHomeId;
    	      this.peerDbSystemId = defaults.peerDbSystemId;
    	      this.peerDbUniqueName = defaults.peerDbUniqueName;
    	      this.peerRole = defaults.peerRole;
    	      this.peerSidPrefix = defaults.peerSidPrefix;
    	      this.peerVmClusterId = defaults.peerVmClusterId;
    	      this.protectionMode = defaults.protectionMode;
    	      this.role = defaults.role;
    	      this.shape = defaults.shape;
    	      this.state = defaults.state;
    	      this.subnetId = defaults.subnetId;
    	      this.timeCreated = defaults.timeCreated;
    	      this.transportType = defaults.transportType;
        }

        public Builder applyLag(String applyLag) {
            this.applyLag = Objects.requireNonNull(applyLag);
            return this;
        }
        public Builder applyRate(String applyRate) {
            this.applyRate = Objects.requireNonNull(applyRate);
            return this;
        }
        public Builder availabilityDomain(String availabilityDomain) {
            this.availabilityDomain = Objects.requireNonNull(availabilityDomain);
            return this;
        }
        public Builder backupNetworkNsgIds(List<String> backupNetworkNsgIds) {
            this.backupNetworkNsgIds = Objects.requireNonNull(backupNetworkNsgIds);
            return this;
        }
        public Builder backupNetworkNsgIds(String... backupNetworkNsgIds) {
            return backupNetworkNsgIds(List.of(backupNetworkNsgIds));
        }
        public Builder createAsync(Boolean createAsync) {
            this.createAsync = Objects.requireNonNull(createAsync);
            return this;
        }
        public Builder creationType(String creationType) {
            this.creationType = Objects.requireNonNull(creationType);
            return this;
        }
        public Builder databaseAdminPassword(String databaseAdminPassword) {
            this.databaseAdminPassword = Objects.requireNonNull(databaseAdminPassword);
            return this;
        }
        public Builder databaseId(String databaseId) {
            this.databaseId = Objects.requireNonNull(databaseId);
            return this;
        }
        public Builder databaseSoftwareImageId(String databaseSoftwareImageId) {
            this.databaseSoftwareImageId = Objects.requireNonNull(databaseSoftwareImageId);
            return this;
        }
        public Builder deleteStandbyDbHomeOnDelete(String deleteStandbyDbHomeOnDelete) {
            this.deleteStandbyDbHomeOnDelete = Objects.requireNonNull(deleteStandbyDbHomeOnDelete);
            return this;
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder hostname(String hostname) {
            this.hostname = Objects.requireNonNull(hostname);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder isActiveDataGuardEnabled(Boolean isActiveDataGuardEnabled) {
            this.isActiveDataGuardEnabled = Objects.requireNonNull(isActiveDataGuardEnabled);
            return this;
        }
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        public Builder nsgIds(List<String> nsgIds) {
            this.nsgIds = Objects.requireNonNull(nsgIds);
            return this;
        }
        public Builder nsgIds(String... nsgIds) {
            return nsgIds(List.of(nsgIds));
        }
        public Builder peerDataGuardAssociationId(String peerDataGuardAssociationId) {
            this.peerDataGuardAssociationId = Objects.requireNonNull(peerDataGuardAssociationId);
            return this;
        }
        public Builder peerDatabaseId(String peerDatabaseId) {
            this.peerDatabaseId = Objects.requireNonNull(peerDatabaseId);
            return this;
        }
        public Builder peerDbHomeId(String peerDbHomeId) {
            this.peerDbHomeId = Objects.requireNonNull(peerDbHomeId);
            return this;
        }
        public Builder peerDbSystemId(String peerDbSystemId) {
            this.peerDbSystemId = Objects.requireNonNull(peerDbSystemId);
            return this;
        }
        public Builder peerDbUniqueName(String peerDbUniqueName) {
            this.peerDbUniqueName = Objects.requireNonNull(peerDbUniqueName);
            return this;
        }
        public Builder peerRole(String peerRole) {
            this.peerRole = Objects.requireNonNull(peerRole);
            return this;
        }
        public Builder peerSidPrefix(String peerSidPrefix) {
            this.peerSidPrefix = Objects.requireNonNull(peerSidPrefix);
            return this;
        }
        public Builder peerVmClusterId(String peerVmClusterId) {
            this.peerVmClusterId = Objects.requireNonNull(peerVmClusterId);
            return this;
        }
        public Builder protectionMode(String protectionMode) {
            this.protectionMode = Objects.requireNonNull(protectionMode);
            return this;
        }
        public Builder role(String role) {
            this.role = Objects.requireNonNull(role);
            return this;
        }
        public Builder shape(String shape) {
            this.shape = Objects.requireNonNull(shape);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder subnetId(String subnetId) {
            this.subnetId = Objects.requireNonNull(subnetId);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder transportType(String transportType) {
            this.transportType = Objects.requireNonNull(transportType);
            return this;
        }        public GetDataGuardAssociationsDataGuardAssociation build() {
            return new GetDataGuardAssociationsDataGuardAssociation(applyLag, applyRate, availabilityDomain, backupNetworkNsgIds, createAsync, creationType, databaseAdminPassword, databaseId, databaseSoftwareImageId, deleteStandbyDbHomeOnDelete, displayName, hostname, id, isActiveDataGuardEnabled, lifecycleDetails, nsgIds, peerDataGuardAssociationId, peerDatabaseId, peerDbHomeId, peerDbSystemId, peerDbUniqueName, peerRole, peerSidPrefix, peerVmClusterId, protectionMode, role, shape, state, subnetId, timeCreated, transportType);
        }
    }
}
