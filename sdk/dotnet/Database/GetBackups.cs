// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetBackups
    {
        /// <summary>
        /// This data source provides the list of Backups in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets a list of backups based on the `databaseId` or `compartmentId` specified. Either one of these query parameters must be provided.
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
        ///     var testBackups = Oci.Database.GetBackups.Invoke(new()
        ///     {
        ///         BackupDestinationType = backupBackupDestinationType,
        ///         CompartmentId = compartmentId,
        ///         DatabaseId = testDatabase.Id,
        ///         ShapeFamily = backupShapeFamily,
        ///         State = backupState,
        ///         TimeExpiryScheduledGreaterThanOrEqualTo = backupTimeExpiryScheduledGreaterThanOrEqualTo,
        ///         TimeExpiryScheduledLessThan = backupTimeExpiryScheduledLessThan,
        ///         Type = backupType,
        ///         Version = backupVersion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetBackupsResult> InvokeAsync(GetBackupsArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetBackupsResult>("oci:Database/getBackups:getBackups", args ?? new GetBackupsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Backups in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets a list of backups based on the `databaseId` or `compartmentId` specified. Either one of these query parameters must be provided.
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
        ///     var testBackups = Oci.Database.GetBackups.Invoke(new()
        ///     {
        ///         BackupDestinationType = backupBackupDestinationType,
        ///         CompartmentId = compartmentId,
        ///         DatabaseId = testDatabase.Id,
        ///         ShapeFamily = backupShapeFamily,
        ///         State = backupState,
        ///         TimeExpiryScheduledGreaterThanOrEqualTo = backupTimeExpiryScheduledGreaterThanOrEqualTo,
        ///         TimeExpiryScheduledLessThan = backupTimeExpiryScheduledLessThan,
        ///         Type = backupType,
        ///         Version = backupVersion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetBackupsResult> Invoke(GetBackupsInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetBackupsResult>("oci:Database/getBackups:getBackups", args ?? new GetBackupsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Backups in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets a list of backups based on the `databaseId` or `compartmentId` specified. Either one of these query parameters must be provided.
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
        ///     var testBackups = Oci.Database.GetBackups.Invoke(new()
        ///     {
        ///         BackupDestinationType = backupBackupDestinationType,
        ///         CompartmentId = compartmentId,
        ///         DatabaseId = testDatabase.Id,
        ///         ShapeFamily = backupShapeFamily,
        ///         State = backupState,
        ///         TimeExpiryScheduledGreaterThanOrEqualTo = backupTimeExpiryScheduledGreaterThanOrEqualTo,
        ///         TimeExpiryScheduledLessThan = backupTimeExpiryScheduledLessThan,
        ///         Type = backupType,
        ///         Version = backupVersion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetBackupsResult> Invoke(GetBackupsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetBackupsResult>("oci:Database/getBackups:getBackups", args ?? new GetBackupsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetBackupsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only resources that match the given backup destination type.
        /// </summary>
        [Input("backupDestinationType")]
        public string? BackupDestinationType { get; set; }

        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
        /// </summary>
        [Input("databaseId")]
        public string? DatabaseId { get; set; }

        [Input("filters")]
        private List<Inputs.GetBackupsFilterArgs>? _filters;
        public List<Inputs.GetBackupsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetBackupsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// If provided, filters the results to the set of database versions which are supported for the given shape family.
        /// </summary>
        [Input("shapeFamily")]
        public string? ShapeFamily { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        /// <summary>
        /// The start of date-time range of expiration for the long term backups to be fetched.
        /// </summary>
        [Input("timeExpiryScheduledGreaterThanOrEqualTo")]
        public string? TimeExpiryScheduledGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// The end of date-time range of expiration for the long term backups to be fetched.
        /// </summary>
        [Input("timeExpiryScheduledLessThan")]
        public string? TimeExpiryScheduledLessThan { get; set; }

        /// <summary>
        /// A filter to return only backups that matches with the given type of Backup.
        /// </summary>
        [Input("type")]
        public string? Type { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given database version.
        /// </summary>
        [Input("version")]
        public string? Version { get; set; }

        public GetBackupsArgs()
        {
        }
        public static new GetBackupsArgs Empty => new GetBackupsArgs();
    }

    public sealed class GetBackupsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only resources that match the given backup destination type.
        /// </summary>
        [Input("backupDestinationType")]
        public Input<string>? BackupDestinationType { get; set; }

        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
        /// </summary>
        [Input("databaseId")]
        public Input<string>? DatabaseId { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetBackupsFilterInputArgs>? _filters;
        public InputList<Inputs.GetBackupsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetBackupsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// If provided, filters the results to the set of database versions which are supported for the given shape family.
        /// </summary>
        [Input("shapeFamily")]
        public Input<string>? ShapeFamily { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The start of date-time range of expiration for the long term backups to be fetched.
        /// </summary>
        [Input("timeExpiryScheduledGreaterThanOrEqualTo")]
        public Input<string>? TimeExpiryScheduledGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// The end of date-time range of expiration for the long term backups to be fetched.
        /// </summary>
        [Input("timeExpiryScheduledLessThan")]
        public Input<string>? TimeExpiryScheduledLessThan { get; set; }

        /// <summary>
        /// A filter to return only backups that matches with the given type of Backup.
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given database version.
        /// </summary>
        [Input("version")]
        public Input<string>? Version { get; set; }

        public GetBackupsInvokeArgs()
        {
        }
        public static new GetBackupsInvokeArgs Empty => new GetBackupsInvokeArgs();
    }


    [OutputType]
    public sealed class GetBackupsResult
    {
        /// <summary>
        /// Type of the backup destination.
        /// </summary>
        public readonly string? BackupDestinationType;
        /// <summary>
        /// The list of backups.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBackupsBackupResult> Backups;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
        /// </summary>
        public readonly string? DatabaseId;
        public readonly ImmutableArray<Outputs.GetBackupsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string? ShapeFamily;
        /// <summary>
        /// The current state of the backup.
        /// </summary>
        public readonly string? State;
        public readonly string? TimeExpiryScheduledGreaterThanOrEqualTo;
        public readonly string? TimeExpiryScheduledLessThan;
        /// <summary>
        /// The type of backup.
        /// </summary>
        public readonly string? Type;
        /// <summary>
        /// Version of the backup's source database
        /// </summary>
        public readonly string? Version;

        [OutputConstructor]
        private GetBackupsResult(
            string? backupDestinationType,

            ImmutableArray<Outputs.GetBackupsBackupResult> backups,

            string? compartmentId,

            string? databaseId,

            ImmutableArray<Outputs.GetBackupsFilterResult> filters,

            string id,

            string? shapeFamily,

            string? state,

            string? timeExpiryScheduledGreaterThanOrEqualTo,

            string? timeExpiryScheduledLessThan,

            string? type,

            string? version)
        {
            BackupDestinationType = backupDestinationType;
            Backups = backups;
            CompartmentId = compartmentId;
            DatabaseId = databaseId;
            Filters = filters;
            Id = id;
            ShapeFamily = shapeFamily;
            State = state;
            TimeExpiryScheduledGreaterThanOrEqualTo = timeExpiryScheduledGreaterThanOrEqualTo;
            TimeExpiryScheduledLessThan = timeExpiryScheduledLessThan;
            Type = type;
            Version = version;
        }
    }
}
