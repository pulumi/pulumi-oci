// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetDataGuardAssociation
    {
        /// <summary>
        /// This data source provides details about a specific Data Guard Association resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets the specified Data Guard association's configuration information.
        /// 
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testDataGuardAssociation = Oci.Database.GetDataGuardAssociation.Invoke(new()
        ///     {
        ///         DataGuardAssociationId = testDataGuardAssociationOciDatabaseDataGuardAssociation.Id,
        ///         DatabaseId = testDatabase.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDataGuardAssociationResult> InvokeAsync(GetDataGuardAssociationArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDataGuardAssociationResult>("oci:Database/getDataGuardAssociation:getDataGuardAssociation", args ?? new GetDataGuardAssociationArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Data Guard Association resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets the specified Data Guard association's configuration information.
        /// 
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testDataGuardAssociation = Oci.Database.GetDataGuardAssociation.Invoke(new()
        ///     {
        ///         DataGuardAssociationId = testDataGuardAssociationOciDatabaseDataGuardAssociation.Id,
        ///         DatabaseId = testDatabase.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDataGuardAssociationResult> Invoke(GetDataGuardAssociationInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDataGuardAssociationResult>("oci:Database/getDataGuardAssociation:getDataGuardAssociation", args ?? new GetDataGuardAssociationInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Data Guard Association resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets the specified Data Guard association's configuration information.
        /// 
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testDataGuardAssociation = Oci.Database.GetDataGuardAssociation.Invoke(new()
        ///     {
        ///         DataGuardAssociationId = testDataGuardAssociationOciDatabaseDataGuardAssociation.Id,
        ///         DatabaseId = testDatabase.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDataGuardAssociationResult> Invoke(GetDataGuardAssociationInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDataGuardAssociationResult>("oci:Database/getDataGuardAssociation:getDataGuardAssociation", args ?? new GetDataGuardAssociationInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDataGuardAssociationArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The Data Guard association's [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("dataGuardAssociationId", required: true)]
        public string DataGuardAssociationId { get; set; } = null!;

        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("databaseId", required: true)]
        public string DatabaseId { get; set; } = null!;

        public GetDataGuardAssociationArgs()
        {
        }
        public static new GetDataGuardAssociationArgs Empty => new GetDataGuardAssociationArgs();
    }

    public sealed class GetDataGuardAssociationInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The Data Guard association's [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("dataGuardAssociationId", required: true)]
        public Input<string> DataGuardAssociationId { get; set; } = null!;

        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("databaseId", required: true)]
        public Input<string> DatabaseId { get; set; } = null!;

        public GetDataGuardAssociationInvokeArgs()
        {
        }
        public static new GetDataGuardAssociationInvokeArgs Empty => new GetDataGuardAssociationInvokeArgs();
    }


    [OutputType]
    public sealed class GetDataGuardAssociationResult
    {
        /// <summary>
        /// The lag time between updates to the primary database and application of the redo data on the standby database, as computed by the reporting database.  Example: `9 seconds`
        /// </summary>
        public readonly string ApplyLag;
        /// <summary>
        /// The rate at which redo logs are synced between the associated databases.  Example: `180 Mb per second`
        /// </summary>
        public readonly string ApplyRate;
        public readonly string AvailabilityDomain;
        public readonly ImmutableArray<string> BackupNetworkNsgIds;
        public readonly int CpuCoreCount;
        public readonly bool CreateAsync;
        public readonly string CreationType;
        public readonly ImmutableArray<Outputs.GetDataGuardAssociationDataCollectionOptionResult> DataCollectionOptions;
        public readonly string DataGuardAssociationId;
        public readonly string DatabaseAdminPassword;
        public readonly ImmutableDictionary<string, string> DatabaseDefinedTags;
        public readonly ImmutableDictionary<string, string> DatabaseFreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the reporting database.
        /// </summary>
        public readonly string DatabaseId;
        public readonly string DatabaseSoftwareImageId;
        public readonly ImmutableDictionary<string, string> DbSystemDefinedTags;
        public readonly ImmutableDictionary<string, string> DbSystemFreeformTags;
        public readonly ImmutableDictionary<string, string> DbSystemSecurityAttributes;
        public readonly string DeleteStandbyDbHomeOnDelete;
        public readonly string DisplayName;
        public readonly string Domain;
        public readonly ImmutableArray<string> FaultDomains;
        public readonly string Hostname;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Data Guard association.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// True if active Data Guard is enabled.
        /// </summary>
        public readonly bool IsActiveDataGuardEnabled;
        public readonly string LicenseModel;
        /// <summary>
        /// Additional information about the current lifecycleState, if available.
        /// </summary>
        public readonly string LifecycleDetails;
        public readonly int MigrateTrigger;
        public readonly int NodeCount;
        public readonly ImmutableArray<string> NsgIds;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer database's Data Guard association.
        /// </summary>
        public readonly string PeerDataGuardAssociationId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated peer database.
        /// </summary>
        public readonly string PeerDatabaseId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home containing the associated peer database.
        /// </summary>
        public readonly string PeerDbHomeId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system containing the associated peer database.
        /// </summary>
        public readonly string PeerDbSystemId;
        public readonly string PeerDbUniqueName;
        /// <summary>
        /// The role of the peer database in this Data Guard association.
        /// </summary>
        public readonly string PeerRole;
        public readonly string PeerSidPrefix;
        public readonly string PeerVmClusterId;
        public readonly string PrivateIp;
        public readonly string PrivateIpV6;
        /// <summary>
        /// The protection mode of this Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
        /// </summary>
        public readonly string ProtectionMode;
        /// <summary>
        /// The role of the reporting database in this Data Guard association.
        /// </summary>
        public readonly string Role;
        public readonly string Shape;
        /// <summary>
        /// The current state of the Data Guard association.
        /// </summary>
        public readonly string State;
        public readonly string StorageVolumePerformanceMode;
        public readonly string SubnetId;
        /// <summary>
        /// The date and time the Data Guard association was created.
        /// </summary>
        public readonly string TimeCreated;
        public readonly string TimeZone;
        /// <summary>
        /// The redo transport type used by this Data Guard association.  For more information, see [Redo Transport Services](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-redo-transport-services.htm#SBYDB00400) in the Oracle Data Guard documentation.
        /// </summary>
        public readonly string TransportType;

        [OutputConstructor]
        private GetDataGuardAssociationResult(
            string applyLag,

            string applyRate,

            string availabilityDomain,

            ImmutableArray<string> backupNetworkNsgIds,

            int cpuCoreCount,

            bool createAsync,

            string creationType,

            ImmutableArray<Outputs.GetDataGuardAssociationDataCollectionOptionResult> dataCollectionOptions,

            string dataGuardAssociationId,

            string databaseAdminPassword,

            ImmutableDictionary<string, string> databaseDefinedTags,

            ImmutableDictionary<string, string> databaseFreeformTags,

            string databaseId,

            string databaseSoftwareImageId,

            ImmutableDictionary<string, string> dbSystemDefinedTags,

            ImmutableDictionary<string, string> dbSystemFreeformTags,

            ImmutableDictionary<string, string> dbSystemSecurityAttributes,

            string deleteStandbyDbHomeOnDelete,

            string displayName,

            string domain,

            ImmutableArray<string> faultDomains,

            string hostname,

            string id,

            bool isActiveDataGuardEnabled,

            string licenseModel,

            string lifecycleDetails,

            int migrateTrigger,

            int nodeCount,

            ImmutableArray<string> nsgIds,

            string peerDataGuardAssociationId,

            string peerDatabaseId,

            string peerDbHomeId,

            string peerDbSystemId,

            string peerDbUniqueName,

            string peerRole,

            string peerSidPrefix,

            string peerVmClusterId,

            string privateIp,

            string privateIpV6,

            string protectionMode,

            string role,

            string shape,

            string state,

            string storageVolumePerformanceMode,

            string subnetId,

            string timeCreated,

            string timeZone,

            string transportType)
        {
            ApplyLag = applyLag;
            ApplyRate = applyRate;
            AvailabilityDomain = availabilityDomain;
            BackupNetworkNsgIds = backupNetworkNsgIds;
            CpuCoreCount = cpuCoreCount;
            CreateAsync = createAsync;
            CreationType = creationType;
            DataCollectionOptions = dataCollectionOptions;
            DataGuardAssociationId = dataGuardAssociationId;
            DatabaseAdminPassword = databaseAdminPassword;
            DatabaseDefinedTags = databaseDefinedTags;
            DatabaseFreeformTags = databaseFreeformTags;
            DatabaseId = databaseId;
            DatabaseSoftwareImageId = databaseSoftwareImageId;
            DbSystemDefinedTags = dbSystemDefinedTags;
            DbSystemFreeformTags = dbSystemFreeformTags;
            DbSystemSecurityAttributes = dbSystemSecurityAttributes;
            DeleteStandbyDbHomeOnDelete = deleteStandbyDbHomeOnDelete;
            DisplayName = displayName;
            Domain = domain;
            FaultDomains = faultDomains;
            Hostname = hostname;
            Id = id;
            IsActiveDataGuardEnabled = isActiveDataGuardEnabled;
            LicenseModel = licenseModel;
            LifecycleDetails = lifecycleDetails;
            MigrateTrigger = migrateTrigger;
            NodeCount = nodeCount;
            NsgIds = nsgIds;
            PeerDataGuardAssociationId = peerDataGuardAssociationId;
            PeerDatabaseId = peerDatabaseId;
            PeerDbHomeId = peerDbHomeId;
            PeerDbSystemId = peerDbSystemId;
            PeerDbUniqueName = peerDbUniqueName;
            PeerRole = peerRole;
            PeerSidPrefix = peerSidPrefix;
            PeerVmClusterId = peerVmClusterId;
            PrivateIp = privateIp;
            PrivateIpV6 = privateIpV6;
            ProtectionMode = protectionMode;
            Role = role;
            Shape = shape;
            State = state;
            StorageVolumePerformanceMode = storageVolumePerformanceMode;
            SubnetId = subnetId;
            TimeCreated = timeCreated;
            TimeZone = timeZone;
            TransportType = transportType;
        }
    }
}
