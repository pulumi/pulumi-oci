// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetBackupDestination
    {
        /// <summary>
        /// This data source provides details about a specific Backup Destination resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets information about the specified backup destination in an Exadata Cloud@Customer system.
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
        ///     var testBackupDestination = Oci.Database.GetBackupDestination.Invoke(new()
        ///     {
        ///         BackupDestinationId = testBackupDestinationOciDatabaseBackupDestination.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetBackupDestinationResult> InvokeAsync(GetBackupDestinationArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetBackupDestinationResult>("oci:Database/getBackupDestination:getBackupDestination", args ?? new GetBackupDestinationArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Backup Destination resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets information about the specified backup destination in an Exadata Cloud@Customer system.
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
        ///     var testBackupDestination = Oci.Database.GetBackupDestination.Invoke(new()
        ///     {
        ///         BackupDestinationId = testBackupDestinationOciDatabaseBackupDestination.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetBackupDestinationResult> Invoke(GetBackupDestinationInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetBackupDestinationResult>("oci:Database/getBackupDestination:getBackupDestination", args ?? new GetBackupDestinationInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Backup Destination resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets information about the specified backup destination in an Exadata Cloud@Customer system.
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
        ///     var testBackupDestination = Oci.Database.GetBackupDestination.Invoke(new()
        ///     {
        ///         BackupDestinationId = testBackupDestinationOciDatabaseBackupDestination.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetBackupDestinationResult> Invoke(GetBackupDestinationInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetBackupDestinationResult>("oci:Database/getBackupDestination:getBackupDestination", args ?? new GetBackupDestinationInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetBackupDestinationArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
        /// </summary>
        [Input("backupDestinationId", required: true)]
        public string BackupDestinationId { get; set; } = null!;

        public GetBackupDestinationArgs()
        {
        }
        public static new GetBackupDestinationArgs Empty => new GetBackupDestinationArgs();
    }

    public sealed class GetBackupDestinationInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
        /// </summary>
        [Input("backupDestinationId", required: true)]
        public Input<string> BackupDestinationId { get; set; } = null!;

        public GetBackupDestinationInvokeArgs()
        {
        }
        public static new GetBackupDestinationInvokeArgs Empty => new GetBackupDestinationInvokeArgs();
    }


    [OutputType]
    public sealed class GetBackupDestinationResult
    {
        /// <summary>
        /// List of databases associated with the backup destination.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBackupDestinationAssociatedDatabaseResult> AssociatedDatabases;
        public readonly string BackupDestinationId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// For a RECOVERY_APPLIANCE backup destination, the connection string for connecting to the Recovery Appliance.
        /// </summary>
        public readonly string ConnectionString;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The user-provided name of the backup destination.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A descriptive text associated with the lifecycleState. Typically contains additional displayable text
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The local directory path on each VM cluster node where the NFS server location is mounted. The local directory path and the NFS server location must each be the same across all of the VM cluster nodes. Ensure that the NFS mount is maintained continuously on all of the VM cluster nodes.
        /// </summary>
        public readonly string LocalMountPointPath;
        public readonly ImmutableArray<Outputs.GetBackupDestinationMountTypeDetailResult> MountTypeDetails;
        /// <summary>
        /// NFS Mount type for backup destination.
        /// </summary>
        public readonly string NfsMountType;
        /// <summary>
        /// Specifies the directory on which to mount the file system
        /// </summary>
        public readonly string NfsServerExport;
        /// <summary>
        /// Host names or IP addresses for NFS Auto mount.
        /// </summary>
        public readonly ImmutableArray<string> NfsServers;
        /// <summary>
        /// The current lifecycle state of the backup destination.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The time when the total storage size and the utilized storage size of the backup destination are updated.
        /// </summary>
        public readonly string TimeAtWhichStorageDetailsAreUpdated;
        /// <summary>
        /// The date and time the backup destination was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The total storage size of the backup destination in GBs, rounded to the nearest integer.
        /// </summary>
        public readonly int TotalStorageSizeInGbs;
        /// <summary>
        /// Type of the backup destination.
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// The total amount of space utilized on the backup destination (in GBs), rounded to the nearest integer.
        /// </summary>
        public readonly int UtilizedStorageSizeInGbs;
        /// <summary>
        /// For a RECOVERY_APPLIANCE backup destination, the Virtual Private Catalog (VPC) users that are used to access the Recovery Appliance.
        /// </summary>
        public readonly ImmutableArray<string> VpcUsers;

        [OutputConstructor]
        private GetBackupDestinationResult(
            ImmutableArray<Outputs.GetBackupDestinationAssociatedDatabaseResult> associatedDatabases,

            string backupDestinationId,

            string compartmentId,

            string connectionString,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            string localMountPointPath,

            ImmutableArray<Outputs.GetBackupDestinationMountTypeDetailResult> mountTypeDetails,

            string nfsMountType,

            string nfsServerExport,

            ImmutableArray<string> nfsServers,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeAtWhichStorageDetailsAreUpdated,

            string timeCreated,

            int totalStorageSizeInGbs,

            string type,

            int utilizedStorageSizeInGbs,

            ImmutableArray<string> vpcUsers)
        {
            AssociatedDatabases = associatedDatabases;
            BackupDestinationId = backupDestinationId;
            CompartmentId = compartmentId;
            ConnectionString = connectionString;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            LocalMountPointPath = localMountPointPath;
            MountTypeDetails = mountTypeDetails;
            NfsMountType = nfsMountType;
            NfsServerExport = nfsServerExport;
            NfsServers = nfsServers;
            State = state;
            SystemTags = systemTags;
            TimeAtWhichStorageDetailsAreUpdated = timeAtWhichStorageDetailsAreUpdated;
            TimeCreated = timeCreated;
            TotalStorageSizeInGbs = totalStorageSizeInGbs;
            Type = type;
            UtilizedStorageSizeInGbs = utilizedStorageSizeInGbs;
            VpcUsers = vpcUsers;
        }
    }
}
