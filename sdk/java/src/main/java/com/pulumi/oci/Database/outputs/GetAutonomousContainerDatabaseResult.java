// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Database.outputs.GetAutonomousContainerDatabaseBackupConfig;
import com.pulumi.oci.Database.outputs.GetAutonomousContainerDatabaseKeyHistoryEntry;
import com.pulumi.oci.Database.outputs.GetAutonomousContainerDatabaseMaintenanceWindow;
import com.pulumi.oci.Database.outputs.GetAutonomousContainerDatabaseMaintenanceWindowDetail;
import com.pulumi.oci.Database.outputs.GetAutonomousContainerDatabasePeerAutonomousContainerDatabaseBackupConfig;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetAutonomousContainerDatabaseResult {
    private final String autonomousContainerDatabaseId;
    /**
     * @return The OCID of the Autonomous Exadata Infrastructure.
     * 
     */
    private final String autonomousExadataInfrastructureId;
    /**
     * @return The OCID of the Autonomous VM Cluster.
     * 
     */
    private final String autonomousVmClusterId;
    /**
     * @return The availability domain of the Autonomous Container Database.
     * 
     */
    private final String availabilityDomain;
    /**
     * @return Backup options for the Autonomous Container Database.
     * 
     */
    private final List<GetAutonomousContainerDatabaseBackupConfig> backupConfigs;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Autonomous Exadata VM Cluster.
     * 
     */
    private final String cloudAutonomousVmClusterId;
    /**
     * @return The OCID of the compartment.
     * 
     */
    private final String compartmentId;
    private final String dbUniqueName;
    /**
     * @return Oracle Database version of the Autonomous Container Database.
     * 
     */
    private final String dbVersion;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    private final Map<String,Object> definedTags;
    /**
     * @return The user-provided name for the Autonomous Container Database.
     * 
     */
    private final String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private final Map<String,Object> freeformTags;
    /**
     * @return The id of the Autonomous Database [Vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts) service key management history entry.
     * 
     */
    private final String id;
    /**
     * @return The infrastructure type this resource belongs to.
     * 
     */
    private final String infrastructureType;
    private final Boolean isAutomaticFailoverEnabled;
    /**
     * @return Key History Entry.
     * 
     */
    private final List<GetAutonomousContainerDatabaseKeyHistoryEntry> keyHistoryEntries;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
     * 
     */
    private final String keyStoreId;
    /**
     * @return The wallet name for Oracle Key Vault.
     * 
     */
    private final String keyStoreWalletName;
    /**
     * @return The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
     * 
     */
    private final String kmsKeyId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance run.
     * 
     */
    private final String lastMaintenanceRunId;
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    private final String lifecycleDetails;
    private final List<GetAutonomousContainerDatabaseMaintenanceWindowDetail> maintenanceWindowDetails;
    /**
     * @return The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
     * 
     */
    private final List<GetAutonomousContainerDatabaseMaintenanceWindow> maintenanceWindows;
    /**
     * @return The amount of memory (in GBs) enabled per each OCPU core in Autonomous VM Cluster.
     * 
     */
    private final Integer memoryPerOracleComputeUnitInGbs;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next maintenance run.
     * 
     */
    private final String nextMaintenanceRunId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last patch applied on the system.
     * 
     */
    private final String patchId;
    /**
     * @return Database patch model preference.
     * 
     */
    private final String patchModel;
    private final List<GetAutonomousContainerDatabasePeerAutonomousContainerDatabaseBackupConfig> peerAutonomousContainerDatabaseBackupConfigs;
    private final String peerAutonomousContainerDatabaseCompartmentId;
    private final String peerAutonomousContainerDatabaseDisplayName;
    private final String peerAutonomousExadataInfrastructureId;
    private final String peerAutonomousVmClusterId;
    private final String peerCloudAutonomousVmClusterId;
    private final String peerDbUniqueName;
    private final String protectionMode;
    /**
     * @return The role of the dataguard enabled Autonomous Container Database.
     * 
     */
    private final String role;
    private final Boolean rotateKeyTrigger;
    /**
     * @return The service level agreement type of the container database. The default is STANDARD.
     * 
     */
    private final String serviceLevelAgreementType;
    /**
     * @return The scheduling detail for the quarterly maintenance window of the standby Autonomous Container Database. This value represents the number of days before scheduled maintenance of the primary database.
     * 
     */
    private final Integer standbyMaintenanceBufferInDays;
    /**
     * @return The current state of the Autonomous Container Database.
     * 
     */
    private final String state;
    /**
     * @return The date and time the Autonomous Container Database was created.
     * 
     */
    private final String timeCreated;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
     * 
     */
    private final String vaultId;

    @CustomType.Constructor
    private GetAutonomousContainerDatabaseResult(
        @CustomType.Parameter("autonomousContainerDatabaseId") String autonomousContainerDatabaseId,
        @CustomType.Parameter("autonomousExadataInfrastructureId") String autonomousExadataInfrastructureId,
        @CustomType.Parameter("autonomousVmClusterId") String autonomousVmClusterId,
        @CustomType.Parameter("availabilityDomain") String availabilityDomain,
        @CustomType.Parameter("backupConfigs") List<GetAutonomousContainerDatabaseBackupConfig> backupConfigs,
        @CustomType.Parameter("cloudAutonomousVmClusterId") String cloudAutonomousVmClusterId,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("dbUniqueName") String dbUniqueName,
        @CustomType.Parameter("dbVersion") String dbVersion,
        @CustomType.Parameter("definedTags") Map<String,Object> definedTags,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("infrastructureType") String infrastructureType,
        @CustomType.Parameter("isAutomaticFailoverEnabled") Boolean isAutomaticFailoverEnabled,
        @CustomType.Parameter("keyHistoryEntries") List<GetAutonomousContainerDatabaseKeyHistoryEntry> keyHistoryEntries,
        @CustomType.Parameter("keyStoreId") String keyStoreId,
        @CustomType.Parameter("keyStoreWalletName") String keyStoreWalletName,
        @CustomType.Parameter("kmsKeyId") String kmsKeyId,
        @CustomType.Parameter("lastMaintenanceRunId") String lastMaintenanceRunId,
        @CustomType.Parameter("lifecycleDetails") String lifecycleDetails,
        @CustomType.Parameter("maintenanceWindowDetails") List<GetAutonomousContainerDatabaseMaintenanceWindowDetail> maintenanceWindowDetails,
        @CustomType.Parameter("maintenanceWindows") List<GetAutonomousContainerDatabaseMaintenanceWindow> maintenanceWindows,
        @CustomType.Parameter("memoryPerOracleComputeUnitInGbs") Integer memoryPerOracleComputeUnitInGbs,
        @CustomType.Parameter("nextMaintenanceRunId") String nextMaintenanceRunId,
        @CustomType.Parameter("patchId") String patchId,
        @CustomType.Parameter("patchModel") String patchModel,
        @CustomType.Parameter("peerAutonomousContainerDatabaseBackupConfigs") List<GetAutonomousContainerDatabasePeerAutonomousContainerDatabaseBackupConfig> peerAutonomousContainerDatabaseBackupConfigs,
        @CustomType.Parameter("peerAutonomousContainerDatabaseCompartmentId") String peerAutonomousContainerDatabaseCompartmentId,
        @CustomType.Parameter("peerAutonomousContainerDatabaseDisplayName") String peerAutonomousContainerDatabaseDisplayName,
        @CustomType.Parameter("peerAutonomousExadataInfrastructureId") String peerAutonomousExadataInfrastructureId,
        @CustomType.Parameter("peerAutonomousVmClusterId") String peerAutonomousVmClusterId,
        @CustomType.Parameter("peerCloudAutonomousVmClusterId") String peerCloudAutonomousVmClusterId,
        @CustomType.Parameter("peerDbUniqueName") String peerDbUniqueName,
        @CustomType.Parameter("protectionMode") String protectionMode,
        @CustomType.Parameter("role") String role,
        @CustomType.Parameter("rotateKeyTrigger") Boolean rotateKeyTrigger,
        @CustomType.Parameter("serviceLevelAgreementType") String serviceLevelAgreementType,
        @CustomType.Parameter("standbyMaintenanceBufferInDays") Integer standbyMaintenanceBufferInDays,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("vaultId") String vaultId) {
        this.autonomousContainerDatabaseId = autonomousContainerDatabaseId;
        this.autonomousExadataInfrastructureId = autonomousExadataInfrastructureId;
        this.autonomousVmClusterId = autonomousVmClusterId;
        this.availabilityDomain = availabilityDomain;
        this.backupConfigs = backupConfigs;
        this.cloudAutonomousVmClusterId = cloudAutonomousVmClusterId;
        this.compartmentId = compartmentId;
        this.dbUniqueName = dbUniqueName;
        this.dbVersion = dbVersion;
        this.definedTags = definedTags;
        this.displayName = displayName;
        this.freeformTags = freeformTags;
        this.id = id;
        this.infrastructureType = infrastructureType;
        this.isAutomaticFailoverEnabled = isAutomaticFailoverEnabled;
        this.keyHistoryEntries = keyHistoryEntries;
        this.keyStoreId = keyStoreId;
        this.keyStoreWalletName = keyStoreWalletName;
        this.kmsKeyId = kmsKeyId;
        this.lastMaintenanceRunId = lastMaintenanceRunId;
        this.lifecycleDetails = lifecycleDetails;
        this.maintenanceWindowDetails = maintenanceWindowDetails;
        this.maintenanceWindows = maintenanceWindows;
        this.memoryPerOracleComputeUnitInGbs = memoryPerOracleComputeUnitInGbs;
        this.nextMaintenanceRunId = nextMaintenanceRunId;
        this.patchId = patchId;
        this.patchModel = patchModel;
        this.peerAutonomousContainerDatabaseBackupConfigs = peerAutonomousContainerDatabaseBackupConfigs;
        this.peerAutonomousContainerDatabaseCompartmentId = peerAutonomousContainerDatabaseCompartmentId;
        this.peerAutonomousContainerDatabaseDisplayName = peerAutonomousContainerDatabaseDisplayName;
        this.peerAutonomousExadataInfrastructureId = peerAutonomousExadataInfrastructureId;
        this.peerAutonomousVmClusterId = peerAutonomousVmClusterId;
        this.peerCloudAutonomousVmClusterId = peerCloudAutonomousVmClusterId;
        this.peerDbUniqueName = peerDbUniqueName;
        this.protectionMode = protectionMode;
        this.role = role;
        this.rotateKeyTrigger = rotateKeyTrigger;
        this.serviceLevelAgreementType = serviceLevelAgreementType;
        this.standbyMaintenanceBufferInDays = standbyMaintenanceBufferInDays;
        this.state = state;
        this.timeCreated = timeCreated;
        this.vaultId = vaultId;
    }

    public String autonomousContainerDatabaseId() {
        return this.autonomousContainerDatabaseId;
    }
    /**
     * @return The OCID of the Autonomous Exadata Infrastructure.
     * 
     */
    public String autonomousExadataInfrastructureId() {
        return this.autonomousExadataInfrastructureId;
    }
    /**
     * @return The OCID of the Autonomous VM Cluster.
     * 
     */
    public String autonomousVmClusterId() {
        return this.autonomousVmClusterId;
    }
    /**
     * @return The availability domain of the Autonomous Container Database.
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return Backup options for the Autonomous Container Database.
     * 
     */
    public List<GetAutonomousContainerDatabaseBackupConfig> backupConfigs() {
        return this.backupConfigs;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Autonomous Exadata VM Cluster.
     * 
     */
    public String cloudAutonomousVmClusterId() {
        return this.cloudAutonomousVmClusterId;
    }
    /**
     * @return The OCID of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public String dbUniqueName() {
        return this.dbUniqueName;
    }
    /**
     * @return Oracle Database version of the Autonomous Container Database.
     * 
     */
    public String dbVersion() {
        return this.dbVersion;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The user-provided name for the Autonomous Container Database.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The id of the Autonomous Database [Vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts) service key management history entry.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The infrastructure type this resource belongs to.
     * 
     */
    public String infrastructureType() {
        return this.infrastructureType;
    }
    public Boolean isAutomaticFailoverEnabled() {
        return this.isAutomaticFailoverEnabled;
    }
    /**
     * @return Key History Entry.
     * 
     */
    public List<GetAutonomousContainerDatabaseKeyHistoryEntry> keyHistoryEntries() {
        return this.keyHistoryEntries;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
     * 
     */
    public String keyStoreId() {
        return this.keyStoreId;
    }
    /**
     * @return The wallet name for Oracle Key Vault.
     * 
     */
    public String keyStoreWalletName() {
        return this.keyStoreWalletName;
    }
    /**
     * @return The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
     * 
     */
    public String kmsKeyId() {
        return this.kmsKeyId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance run.
     * 
     */
    public String lastMaintenanceRunId() {
        return this.lastMaintenanceRunId;
    }
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    public List<GetAutonomousContainerDatabaseMaintenanceWindowDetail> maintenanceWindowDetails() {
        return this.maintenanceWindowDetails;
    }
    /**
     * @return The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
     * 
     */
    public List<GetAutonomousContainerDatabaseMaintenanceWindow> maintenanceWindows() {
        return this.maintenanceWindows;
    }
    /**
     * @return The amount of memory (in GBs) enabled per each OCPU core in Autonomous VM Cluster.
     * 
     */
    public Integer memoryPerOracleComputeUnitInGbs() {
        return this.memoryPerOracleComputeUnitInGbs;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next maintenance run.
     * 
     */
    public String nextMaintenanceRunId() {
        return this.nextMaintenanceRunId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last patch applied on the system.
     * 
     */
    public String patchId() {
        return this.patchId;
    }
    /**
     * @return Database patch model preference.
     * 
     */
    public String patchModel() {
        return this.patchModel;
    }
    public List<GetAutonomousContainerDatabasePeerAutonomousContainerDatabaseBackupConfig> peerAutonomousContainerDatabaseBackupConfigs() {
        return this.peerAutonomousContainerDatabaseBackupConfigs;
    }
    public String peerAutonomousContainerDatabaseCompartmentId() {
        return this.peerAutonomousContainerDatabaseCompartmentId;
    }
    public String peerAutonomousContainerDatabaseDisplayName() {
        return this.peerAutonomousContainerDatabaseDisplayName;
    }
    public String peerAutonomousExadataInfrastructureId() {
        return this.peerAutonomousExadataInfrastructureId;
    }
    public String peerAutonomousVmClusterId() {
        return this.peerAutonomousVmClusterId;
    }
    public String peerCloudAutonomousVmClusterId() {
        return this.peerCloudAutonomousVmClusterId;
    }
    public String peerDbUniqueName() {
        return this.peerDbUniqueName;
    }
    public String protectionMode() {
        return this.protectionMode;
    }
    /**
     * @return The role of the dataguard enabled Autonomous Container Database.
     * 
     */
    public String role() {
        return this.role;
    }
    public Boolean rotateKeyTrigger() {
        return this.rotateKeyTrigger;
    }
    /**
     * @return The service level agreement type of the container database. The default is STANDARD.
     * 
     */
    public String serviceLevelAgreementType() {
        return this.serviceLevelAgreementType;
    }
    /**
     * @return The scheduling detail for the quarterly maintenance window of the standby Autonomous Container Database. This value represents the number of days before scheduled maintenance of the primary database.
     * 
     */
    public Integer standbyMaintenanceBufferInDays() {
        return this.standbyMaintenanceBufferInDays;
    }
    /**
     * @return The current state of the Autonomous Container Database.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the Autonomous Container Database was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
     * 
     */
    public String vaultId() {
        return this.vaultId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutonomousContainerDatabaseResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String autonomousContainerDatabaseId;
        private String autonomousExadataInfrastructureId;
        private String autonomousVmClusterId;
        private String availabilityDomain;
        private List<GetAutonomousContainerDatabaseBackupConfig> backupConfigs;
        private String cloudAutonomousVmClusterId;
        private String compartmentId;
        private String dbUniqueName;
        private String dbVersion;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private String infrastructureType;
        private Boolean isAutomaticFailoverEnabled;
        private List<GetAutonomousContainerDatabaseKeyHistoryEntry> keyHistoryEntries;
        private String keyStoreId;
        private String keyStoreWalletName;
        private String kmsKeyId;
        private String lastMaintenanceRunId;
        private String lifecycleDetails;
        private List<GetAutonomousContainerDatabaseMaintenanceWindowDetail> maintenanceWindowDetails;
        private List<GetAutonomousContainerDatabaseMaintenanceWindow> maintenanceWindows;
        private Integer memoryPerOracleComputeUnitInGbs;
        private String nextMaintenanceRunId;
        private String patchId;
        private String patchModel;
        private List<GetAutonomousContainerDatabasePeerAutonomousContainerDatabaseBackupConfig> peerAutonomousContainerDatabaseBackupConfigs;
        private String peerAutonomousContainerDatabaseCompartmentId;
        private String peerAutonomousContainerDatabaseDisplayName;
        private String peerAutonomousExadataInfrastructureId;
        private String peerAutonomousVmClusterId;
        private String peerCloudAutonomousVmClusterId;
        private String peerDbUniqueName;
        private String protectionMode;
        private String role;
        private Boolean rotateKeyTrigger;
        private String serviceLevelAgreementType;
        private Integer standbyMaintenanceBufferInDays;
        private String state;
        private String timeCreated;
        private String vaultId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetAutonomousContainerDatabaseResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.autonomousContainerDatabaseId = defaults.autonomousContainerDatabaseId;
    	      this.autonomousExadataInfrastructureId = defaults.autonomousExadataInfrastructureId;
    	      this.autonomousVmClusterId = defaults.autonomousVmClusterId;
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.backupConfigs = defaults.backupConfigs;
    	      this.cloudAutonomousVmClusterId = defaults.cloudAutonomousVmClusterId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.dbUniqueName = defaults.dbUniqueName;
    	      this.dbVersion = defaults.dbVersion;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.infrastructureType = defaults.infrastructureType;
    	      this.isAutomaticFailoverEnabled = defaults.isAutomaticFailoverEnabled;
    	      this.keyHistoryEntries = defaults.keyHistoryEntries;
    	      this.keyStoreId = defaults.keyStoreId;
    	      this.keyStoreWalletName = defaults.keyStoreWalletName;
    	      this.kmsKeyId = defaults.kmsKeyId;
    	      this.lastMaintenanceRunId = defaults.lastMaintenanceRunId;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.maintenanceWindowDetails = defaults.maintenanceWindowDetails;
    	      this.maintenanceWindows = defaults.maintenanceWindows;
    	      this.memoryPerOracleComputeUnitInGbs = defaults.memoryPerOracleComputeUnitInGbs;
    	      this.nextMaintenanceRunId = defaults.nextMaintenanceRunId;
    	      this.patchId = defaults.patchId;
    	      this.patchModel = defaults.patchModel;
    	      this.peerAutonomousContainerDatabaseBackupConfigs = defaults.peerAutonomousContainerDatabaseBackupConfigs;
    	      this.peerAutonomousContainerDatabaseCompartmentId = defaults.peerAutonomousContainerDatabaseCompartmentId;
    	      this.peerAutonomousContainerDatabaseDisplayName = defaults.peerAutonomousContainerDatabaseDisplayName;
    	      this.peerAutonomousExadataInfrastructureId = defaults.peerAutonomousExadataInfrastructureId;
    	      this.peerAutonomousVmClusterId = defaults.peerAutonomousVmClusterId;
    	      this.peerCloudAutonomousVmClusterId = defaults.peerCloudAutonomousVmClusterId;
    	      this.peerDbUniqueName = defaults.peerDbUniqueName;
    	      this.protectionMode = defaults.protectionMode;
    	      this.role = defaults.role;
    	      this.rotateKeyTrigger = defaults.rotateKeyTrigger;
    	      this.serviceLevelAgreementType = defaults.serviceLevelAgreementType;
    	      this.standbyMaintenanceBufferInDays = defaults.standbyMaintenanceBufferInDays;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.vaultId = defaults.vaultId;
        }

        public Builder autonomousContainerDatabaseId(String autonomousContainerDatabaseId) {
            this.autonomousContainerDatabaseId = Objects.requireNonNull(autonomousContainerDatabaseId);
            return this;
        }
        public Builder autonomousExadataInfrastructureId(String autonomousExadataInfrastructureId) {
            this.autonomousExadataInfrastructureId = Objects.requireNonNull(autonomousExadataInfrastructureId);
            return this;
        }
        public Builder autonomousVmClusterId(String autonomousVmClusterId) {
            this.autonomousVmClusterId = Objects.requireNonNull(autonomousVmClusterId);
            return this;
        }
        public Builder availabilityDomain(String availabilityDomain) {
            this.availabilityDomain = Objects.requireNonNull(availabilityDomain);
            return this;
        }
        public Builder backupConfigs(List<GetAutonomousContainerDatabaseBackupConfig> backupConfigs) {
            this.backupConfigs = Objects.requireNonNull(backupConfigs);
            return this;
        }
        public Builder backupConfigs(GetAutonomousContainerDatabaseBackupConfig... backupConfigs) {
            return backupConfigs(List.of(backupConfigs));
        }
        public Builder cloudAutonomousVmClusterId(String cloudAutonomousVmClusterId) {
            this.cloudAutonomousVmClusterId = Objects.requireNonNull(cloudAutonomousVmClusterId);
            return this;
        }
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder dbUniqueName(String dbUniqueName) {
            this.dbUniqueName = Objects.requireNonNull(dbUniqueName);
            return this;
        }
        public Builder dbVersion(String dbVersion) {
            this.dbVersion = Objects.requireNonNull(dbVersion);
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
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder infrastructureType(String infrastructureType) {
            this.infrastructureType = Objects.requireNonNull(infrastructureType);
            return this;
        }
        public Builder isAutomaticFailoverEnabled(Boolean isAutomaticFailoverEnabled) {
            this.isAutomaticFailoverEnabled = Objects.requireNonNull(isAutomaticFailoverEnabled);
            return this;
        }
        public Builder keyHistoryEntries(List<GetAutonomousContainerDatabaseKeyHistoryEntry> keyHistoryEntries) {
            this.keyHistoryEntries = Objects.requireNonNull(keyHistoryEntries);
            return this;
        }
        public Builder keyHistoryEntries(GetAutonomousContainerDatabaseKeyHistoryEntry... keyHistoryEntries) {
            return keyHistoryEntries(List.of(keyHistoryEntries));
        }
        public Builder keyStoreId(String keyStoreId) {
            this.keyStoreId = Objects.requireNonNull(keyStoreId);
            return this;
        }
        public Builder keyStoreWalletName(String keyStoreWalletName) {
            this.keyStoreWalletName = Objects.requireNonNull(keyStoreWalletName);
            return this;
        }
        public Builder kmsKeyId(String kmsKeyId) {
            this.kmsKeyId = Objects.requireNonNull(kmsKeyId);
            return this;
        }
        public Builder lastMaintenanceRunId(String lastMaintenanceRunId) {
            this.lastMaintenanceRunId = Objects.requireNonNull(lastMaintenanceRunId);
            return this;
        }
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        public Builder maintenanceWindowDetails(List<GetAutonomousContainerDatabaseMaintenanceWindowDetail> maintenanceWindowDetails) {
            this.maintenanceWindowDetails = Objects.requireNonNull(maintenanceWindowDetails);
            return this;
        }
        public Builder maintenanceWindowDetails(GetAutonomousContainerDatabaseMaintenanceWindowDetail... maintenanceWindowDetails) {
            return maintenanceWindowDetails(List.of(maintenanceWindowDetails));
        }
        public Builder maintenanceWindows(List<GetAutonomousContainerDatabaseMaintenanceWindow> maintenanceWindows) {
            this.maintenanceWindows = Objects.requireNonNull(maintenanceWindows);
            return this;
        }
        public Builder maintenanceWindows(GetAutonomousContainerDatabaseMaintenanceWindow... maintenanceWindows) {
            return maintenanceWindows(List.of(maintenanceWindows));
        }
        public Builder memoryPerOracleComputeUnitInGbs(Integer memoryPerOracleComputeUnitInGbs) {
            this.memoryPerOracleComputeUnitInGbs = Objects.requireNonNull(memoryPerOracleComputeUnitInGbs);
            return this;
        }
        public Builder nextMaintenanceRunId(String nextMaintenanceRunId) {
            this.nextMaintenanceRunId = Objects.requireNonNull(nextMaintenanceRunId);
            return this;
        }
        public Builder patchId(String patchId) {
            this.patchId = Objects.requireNonNull(patchId);
            return this;
        }
        public Builder patchModel(String patchModel) {
            this.patchModel = Objects.requireNonNull(patchModel);
            return this;
        }
        public Builder peerAutonomousContainerDatabaseBackupConfigs(List<GetAutonomousContainerDatabasePeerAutonomousContainerDatabaseBackupConfig> peerAutonomousContainerDatabaseBackupConfigs) {
            this.peerAutonomousContainerDatabaseBackupConfigs = Objects.requireNonNull(peerAutonomousContainerDatabaseBackupConfigs);
            return this;
        }
        public Builder peerAutonomousContainerDatabaseBackupConfigs(GetAutonomousContainerDatabasePeerAutonomousContainerDatabaseBackupConfig... peerAutonomousContainerDatabaseBackupConfigs) {
            return peerAutonomousContainerDatabaseBackupConfigs(List.of(peerAutonomousContainerDatabaseBackupConfigs));
        }
        public Builder peerAutonomousContainerDatabaseCompartmentId(String peerAutonomousContainerDatabaseCompartmentId) {
            this.peerAutonomousContainerDatabaseCompartmentId = Objects.requireNonNull(peerAutonomousContainerDatabaseCompartmentId);
            return this;
        }
        public Builder peerAutonomousContainerDatabaseDisplayName(String peerAutonomousContainerDatabaseDisplayName) {
            this.peerAutonomousContainerDatabaseDisplayName = Objects.requireNonNull(peerAutonomousContainerDatabaseDisplayName);
            return this;
        }
        public Builder peerAutonomousExadataInfrastructureId(String peerAutonomousExadataInfrastructureId) {
            this.peerAutonomousExadataInfrastructureId = Objects.requireNonNull(peerAutonomousExadataInfrastructureId);
            return this;
        }
        public Builder peerAutonomousVmClusterId(String peerAutonomousVmClusterId) {
            this.peerAutonomousVmClusterId = Objects.requireNonNull(peerAutonomousVmClusterId);
            return this;
        }
        public Builder peerCloudAutonomousVmClusterId(String peerCloudAutonomousVmClusterId) {
            this.peerCloudAutonomousVmClusterId = Objects.requireNonNull(peerCloudAutonomousVmClusterId);
            return this;
        }
        public Builder peerDbUniqueName(String peerDbUniqueName) {
            this.peerDbUniqueName = Objects.requireNonNull(peerDbUniqueName);
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
        public Builder rotateKeyTrigger(Boolean rotateKeyTrigger) {
            this.rotateKeyTrigger = Objects.requireNonNull(rotateKeyTrigger);
            return this;
        }
        public Builder serviceLevelAgreementType(String serviceLevelAgreementType) {
            this.serviceLevelAgreementType = Objects.requireNonNull(serviceLevelAgreementType);
            return this;
        }
        public Builder standbyMaintenanceBufferInDays(Integer standbyMaintenanceBufferInDays) {
            this.standbyMaintenanceBufferInDays = Objects.requireNonNull(standbyMaintenanceBufferInDays);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder vaultId(String vaultId) {
            this.vaultId = Objects.requireNonNull(vaultId);
            return this;
        }        public GetAutonomousContainerDatabaseResult build() {
            return new GetAutonomousContainerDatabaseResult(autonomousContainerDatabaseId, autonomousExadataInfrastructureId, autonomousVmClusterId, availabilityDomain, backupConfigs, cloudAutonomousVmClusterId, compartmentId, dbUniqueName, dbVersion, definedTags, displayName, freeformTags, id, infrastructureType, isAutomaticFailoverEnabled, keyHistoryEntries, keyStoreId, keyStoreWalletName, kmsKeyId, lastMaintenanceRunId, lifecycleDetails, maintenanceWindowDetails, maintenanceWindows, memoryPerOracleComputeUnitInGbs, nextMaintenanceRunId, patchId, patchModel, peerAutonomousContainerDatabaseBackupConfigs, peerAutonomousContainerDatabaseCompartmentId, peerAutonomousContainerDatabaseDisplayName, peerAutonomousExadataInfrastructureId, peerAutonomousVmClusterId, peerCloudAutonomousVmClusterId, peerDbUniqueName, protectionMode, role, rotateKeyTrigger, serviceLevelAgreementType, standbyMaintenanceBufferInDays, state, timeCreated, vaultId);
        }
    }
}
