// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Psql
{
    public static class GetBackups
    {
        /// <summary>
        /// This data source provides the list of Backups in Oracle Cloud Infrastructure Psql service.
        /// 
        /// Returns a list of backups.
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
        ///     var testBackups = Oci.Psql.GetBackups.Invoke(new()
        ///     {
        ///         BackupId = testBackup.Id,
        ///         CompartmentId = compartmentId,
        ///         DisplayName = backupDisplayName,
        ///         Id = backupId,
        ///         State = backupState,
        ///         TimeEnded = backupTimeEnded,
        ///         TimeStarted = backupTimeStarted,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetBackupsResult> InvokeAsync(GetBackupsArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetBackupsResult>("oci:Psql/getBackups:getBackups", args ?? new GetBackupsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Backups in Oracle Cloud Infrastructure Psql service.
        /// 
        /// Returns a list of backups.
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
        ///     var testBackups = Oci.Psql.GetBackups.Invoke(new()
        ///     {
        ///         BackupId = testBackup.Id,
        ///         CompartmentId = compartmentId,
        ///         DisplayName = backupDisplayName,
        ///         Id = backupId,
        ///         State = backupState,
        ///         TimeEnded = backupTimeEnded,
        ///         TimeStarted = backupTimeStarted,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetBackupsResult> Invoke(GetBackupsInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetBackupsResult>("oci:Psql/getBackups:getBackups", args ?? new GetBackupsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Backups in Oracle Cloud Infrastructure Psql service.
        /// 
        /// Returns a list of backups.
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
        ///     var testBackups = Oci.Psql.GetBackups.Invoke(new()
        ///     {
        ///         BackupId = testBackup.Id,
        ///         CompartmentId = compartmentId,
        ///         DisplayName = backupDisplayName,
        ///         Id = backupId,
        ///         State = backupState,
        ///         TimeEnded = backupTimeEnded,
        ///         TimeStarted = backupTimeStarted,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetBackupsResult> Invoke(GetBackupsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetBackupsResult>("oci:Psql/getBackups:getBackups", args ?? new GetBackupsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetBackupsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A unique identifier for the backup.
        /// </summary>
        [Input("backupId")]
        public string? BackupId { get; set; }

        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetBackupsFilterArgs>? _filters;
        public List<Inputs.GetBackupsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetBackupsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A unique identifier for the database system.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// A filter to return only resources if their `lifecycleState` matches the given `lifecycleState`.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        /// <summary>
        /// The end date for getting backups. An [RFC 3339](https://tools.ietf.org/rfc/rfc3339) formatted datetime string.
        /// </summary>
        [Input("timeEnded")]
        public string? TimeEnded { get; set; }

        /// <summary>
        /// The start date for getting backups. An [RFC 3339](https://tools.ietf.org/rfc/rfc3339) formatted datetime string.
        /// </summary>
        [Input("timeStarted")]
        public string? TimeStarted { get; set; }

        public GetBackupsArgs()
        {
        }
        public static new GetBackupsArgs Empty => new GetBackupsArgs();
    }

    public sealed class GetBackupsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A unique identifier for the backup.
        /// </summary>
        [Input("backupId")]
        public Input<string>? BackupId { get; set; }

        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetBackupsFilterInputArgs>? _filters;
        public InputList<Inputs.GetBackupsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetBackupsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A unique identifier for the database system.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// A filter to return only resources if their `lifecycleState` matches the given `lifecycleState`.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The end date for getting backups. An [RFC 3339](https://tools.ietf.org/rfc/rfc3339) formatted datetime string.
        /// </summary>
        [Input("timeEnded")]
        public Input<string>? TimeEnded { get; set; }

        /// <summary>
        /// The start date for getting backups. An [RFC 3339](https://tools.ietf.org/rfc/rfc3339) formatted datetime string.
        /// </summary>
        [Input("timeStarted")]
        public Input<string>? TimeStarted { get; set; }

        public GetBackupsInvokeArgs()
        {
        }
        public static new GetBackupsInvokeArgs Empty => new GetBackupsInvokeArgs();
    }


    [OutputType]
    public sealed class GetBackupsResult
    {
        /// <summary>
        /// The list of backup_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBackupsBackupCollectionResult> BackupCollections;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup in the source region
        /// </summary>
        public readonly string? BackupId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the backup.
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// A user-friendly display name for the backup. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetBackupsFilterResult> Filters;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The current state of the backup.
        /// </summary>
        public readonly string? State;
        public readonly string? TimeEnded;
        public readonly string? TimeStarted;

        [OutputConstructor]
        private GetBackupsResult(
            ImmutableArray<Outputs.GetBackupsBackupCollectionResult> backupCollections,

            string? backupId,

            string? compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetBackupsFilterResult> filters,

            string? id,

            string? state,

            string? timeEnded,

            string? timeStarted)
        {
            BackupCollections = backupCollections;
            BackupId = backupId;
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
            TimeEnded = timeEnded;
            TimeStarted = timeStarted;
        }
    }
}
