// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetAutonomousContainerDatabase
    {
        /// <summary>
        /// This data source provides details about a specific Autonomous Container Database resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets information about the specified Autonomous Container Database.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testAutonomousContainerDatabase = Oci.Database.GetAutonomousContainerDatabase.Invoke(new()
        ///     {
        ///         AutonomousContainerDatabaseId = oci_database_autonomous_container_database.Test_autonomous_container_database.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetAutonomousContainerDatabaseResult> InvokeAsync(GetAutonomousContainerDatabaseArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetAutonomousContainerDatabaseResult>("oci:Database/getAutonomousContainerDatabase:getAutonomousContainerDatabase", args ?? new GetAutonomousContainerDatabaseArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Autonomous Container Database resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets information about the specified Autonomous Container Database.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testAutonomousContainerDatabase = Oci.Database.GetAutonomousContainerDatabase.Invoke(new()
        ///     {
        ///         AutonomousContainerDatabaseId = oci_database_autonomous_container_database.Test_autonomous_container_database.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetAutonomousContainerDatabaseResult> Invoke(GetAutonomousContainerDatabaseInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetAutonomousContainerDatabaseResult>("oci:Database/getAutonomousContainerDatabase:getAutonomousContainerDatabase", args ?? new GetAutonomousContainerDatabaseInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAutonomousContainerDatabaseArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("autonomousContainerDatabaseId", required: true)]
        public string AutonomousContainerDatabaseId { get; set; } = null!;

        public GetAutonomousContainerDatabaseArgs()
        {
        }
        public static new GetAutonomousContainerDatabaseArgs Empty => new GetAutonomousContainerDatabaseArgs();
    }

    public sealed class GetAutonomousContainerDatabaseInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("autonomousContainerDatabaseId", required: true)]
        public Input<string> AutonomousContainerDatabaseId { get; set; } = null!;

        public GetAutonomousContainerDatabaseInvokeArgs()
        {
        }
        public static new GetAutonomousContainerDatabaseInvokeArgs Empty => new GetAutonomousContainerDatabaseInvokeArgs();
    }


    [OutputType]
    public sealed class GetAutonomousContainerDatabaseResult
    {
        public readonly string AutonomousContainerDatabaseId;
        /// <summary>
        /// **No longer used.** For Autonomous Database on dedicated Exadata infrastructure, the container database is created within a specified `cloudAutonomousVmCluster`.
        /// </summary>
        public readonly string AutonomousExadataInfrastructureId;
        /// <summary>
        /// The OCID of the Autonomous VM Cluster.
        /// </summary>
        public readonly string AutonomousVmClusterId;
        /// <summary>
        /// The availability domain of the Autonomous Container Database.
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// Sum of OCPUs available on the Autonomous VM Cluster + Sum of fractional OCPUs available in the Autonomous Container Database.
        /// </summary>
        public readonly double AvailableCpus;
        /// <summary>
        /// Backup options for the Autonomous Container Database.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAutonomousContainerDatabaseBackupConfigResult> BackupConfigs;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Autonomous Exadata VM Cluster.
        /// </summary>
        public readonly string CloudAutonomousVmClusterId;
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        public readonly string DbUniqueName;
        /// <summary>
        /// Oracle Database version of the Autonomous Container Database.
        /// </summary>
        public readonly string DbVersion;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The user-provided name for the Autonomous Container Database.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The id of the Autonomous Database [Vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts) service key management history entry.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The infrastructure type this resource belongs to.
        /// </summary>
        public readonly string InfrastructureType;
        public readonly bool IsAutomaticFailoverEnabled;
        /// <summary>
        /// Key History Entry.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAutonomousContainerDatabaseKeyHistoryEntryResult> KeyHistoryEntries;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
        /// </summary>
        public readonly string KeyStoreId;
        /// <summary>
        /// The wallet name for Oracle Key Vault.
        /// </summary>
        public readonly string KeyStoreWalletName;
        /// <summary>
        /// The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
        /// </summary>
        public readonly string KmsKeyId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance run.
        /// </summary>
        public readonly string LastMaintenanceRunId;
        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        public readonly ImmutableArray<Outputs.GetAutonomousContainerDatabaseMaintenanceWindowDetailResult> MaintenanceWindowDetails;
        /// <summary>
        /// The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAutonomousContainerDatabaseMaintenanceWindowResult> MaintenanceWindows;
        /// <summary>
        /// The amount of memory (in GBs) enabled per each OCPU core in Autonomous VM Cluster.
        /// </summary>
        public readonly int MemoryPerOracleComputeUnitInGbs;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next maintenance run.
        /// </summary>
        public readonly string NextMaintenanceRunId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last patch applied on the system.
        /// </summary>
        public readonly string PatchId;
        /// <summary>
        /// Database patch model preference.
        /// </summary>
        public readonly string PatchModel;
        public readonly ImmutableArray<Outputs.GetAutonomousContainerDatabasePeerAutonomousContainerDatabaseBackupConfigResult> PeerAutonomousContainerDatabaseBackupConfigs;
        public readonly string PeerAutonomousContainerDatabaseCompartmentId;
        public readonly string PeerAutonomousContainerDatabaseDisplayName;
        public readonly string PeerAutonomousExadataInfrastructureId;
        public readonly string PeerAutonomousVmClusterId;
        public readonly string PeerCloudAutonomousVmClusterId;
        public readonly string PeerDbUniqueName;
        public readonly string ProtectionMode;
        /// <summary>
        /// An array of CPU values that can be used to successfully provision a single Autonomous Database.
        /// </summary>
        public readonly ImmutableArray<double> ProvisionableCpuses;
        /// <summary>
        /// CPU cores that continue to be included in the count of OCPUs available to the Autonomous Container Database even after one of its Autonomous Database is terminated or scaled down. You can release them to the available OCPUs at its parent AVMC level by restarting the Autonomous Container Database.
        /// </summary>
        public readonly double ReclaimableCpus;
        /// <summary>
        /// The role of the Autonomous Data Guard-enabled Autonomous Container Database.
        /// </summary>
        public readonly string Role;
        public readonly bool RotateKeyTrigger;
        /// <summary>
        /// The service level agreement type of the container database. The default is STANDARD.
        /// </summary>
        public readonly string ServiceLevelAgreementType;
        /// <summary>
        /// The scheduling detail for the quarterly maintenance window of the standby Autonomous Container Database. This value represents the number of days before scheduled maintenance of the primary database.
        /// </summary>
        public readonly int StandbyMaintenanceBufferInDays;
        /// <summary>
        /// The current state of the Autonomous Container Database.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the Autonomous Container Database was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The number of CPU cores allocated to the Autonomous VM cluster.
        /// </summary>
        public readonly int TotalCpus;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
        /// </summary>
        public readonly string VaultId;

        [OutputConstructor]
        private GetAutonomousContainerDatabaseResult(
            string autonomousContainerDatabaseId,

            string autonomousExadataInfrastructureId,

            string autonomousVmClusterId,

            string availabilityDomain,

            double availableCpus,

            ImmutableArray<Outputs.GetAutonomousContainerDatabaseBackupConfigResult> backupConfigs,

            string cloudAutonomousVmClusterId,

            string compartmentId,

            string dbUniqueName,

            string dbVersion,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string infrastructureType,

            bool isAutomaticFailoverEnabled,

            ImmutableArray<Outputs.GetAutonomousContainerDatabaseKeyHistoryEntryResult> keyHistoryEntries,

            string keyStoreId,

            string keyStoreWalletName,

            string kmsKeyId,

            string lastMaintenanceRunId,

            string lifecycleDetails,

            ImmutableArray<Outputs.GetAutonomousContainerDatabaseMaintenanceWindowDetailResult> maintenanceWindowDetails,

            ImmutableArray<Outputs.GetAutonomousContainerDatabaseMaintenanceWindowResult> maintenanceWindows,

            int memoryPerOracleComputeUnitInGbs,

            string nextMaintenanceRunId,

            string patchId,

            string patchModel,

            ImmutableArray<Outputs.GetAutonomousContainerDatabasePeerAutonomousContainerDatabaseBackupConfigResult> peerAutonomousContainerDatabaseBackupConfigs,

            string peerAutonomousContainerDatabaseCompartmentId,

            string peerAutonomousContainerDatabaseDisplayName,

            string peerAutonomousExadataInfrastructureId,

            string peerAutonomousVmClusterId,

            string peerCloudAutonomousVmClusterId,

            string peerDbUniqueName,

            string protectionMode,

            ImmutableArray<double> provisionableCpuses,

            double reclaimableCpus,

            string role,

            bool rotateKeyTrigger,

            string serviceLevelAgreementType,

            int standbyMaintenanceBufferInDays,

            string state,

            string timeCreated,

            int totalCpus,

            string vaultId)
        {
            AutonomousContainerDatabaseId = autonomousContainerDatabaseId;
            AutonomousExadataInfrastructureId = autonomousExadataInfrastructureId;
            AutonomousVmClusterId = autonomousVmClusterId;
            AvailabilityDomain = availabilityDomain;
            AvailableCpus = availableCpus;
            BackupConfigs = backupConfigs;
            CloudAutonomousVmClusterId = cloudAutonomousVmClusterId;
            CompartmentId = compartmentId;
            DbUniqueName = dbUniqueName;
            DbVersion = dbVersion;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            InfrastructureType = infrastructureType;
            IsAutomaticFailoverEnabled = isAutomaticFailoverEnabled;
            KeyHistoryEntries = keyHistoryEntries;
            KeyStoreId = keyStoreId;
            KeyStoreWalletName = keyStoreWalletName;
            KmsKeyId = kmsKeyId;
            LastMaintenanceRunId = lastMaintenanceRunId;
            LifecycleDetails = lifecycleDetails;
            MaintenanceWindowDetails = maintenanceWindowDetails;
            MaintenanceWindows = maintenanceWindows;
            MemoryPerOracleComputeUnitInGbs = memoryPerOracleComputeUnitInGbs;
            NextMaintenanceRunId = nextMaintenanceRunId;
            PatchId = patchId;
            PatchModel = patchModel;
            PeerAutonomousContainerDatabaseBackupConfigs = peerAutonomousContainerDatabaseBackupConfigs;
            PeerAutonomousContainerDatabaseCompartmentId = peerAutonomousContainerDatabaseCompartmentId;
            PeerAutonomousContainerDatabaseDisplayName = peerAutonomousContainerDatabaseDisplayName;
            PeerAutonomousExadataInfrastructureId = peerAutonomousExadataInfrastructureId;
            PeerAutonomousVmClusterId = peerAutonomousVmClusterId;
            PeerCloudAutonomousVmClusterId = peerCloudAutonomousVmClusterId;
            PeerDbUniqueName = peerDbUniqueName;
            ProtectionMode = protectionMode;
            ProvisionableCpuses = provisionableCpuses;
            ReclaimableCpus = reclaimableCpus;
            Role = role;
            RotateKeyTrigger = rotateKeyTrigger;
            ServiceLevelAgreementType = serviceLevelAgreementType;
            StandbyMaintenanceBufferInDays = standbyMaintenanceBufferInDays;
            State = state;
            TimeCreated = timeCreated;
            TotalCpus = totalCpus;
            VaultId = vaultId;
        }
    }
}