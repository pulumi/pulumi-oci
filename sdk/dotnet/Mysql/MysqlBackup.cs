// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Mysql
{
    /// <summary>
    /// This resource provides the Mysql Backup resource in Oracle Cloud Infrastructure MySQL Database service.
    /// 
    /// Create a backup of a DB System.
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
    ///     var testMysqlBackup = new Oci.Mysql.MysqlBackup("test_mysql_backup", new()
    ///     {
    ///         DbSystemId = testDbSystem.Id,
    ///         BackupType = mysqlBackupBackupType,
    ///         DefinedTags = 
    ///         {
    ///             { "foo-namespace.bar-key", "value" },
    ///         },
    ///         Description = mysqlBackupDescription,
    ///         DisplayName = mysqlBackupDisplayName,
    ///         FreeformTags = 
    ///         {
    ///             { "bar-key", "value" },
    ///         },
    ///         RetentionInDays = mysqlBackupRetentionInDays,
    ///         SoftDelete = mysqlBackupSoftDelete,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// MysqlBackups can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:Mysql/mysqlBackup:MysqlBackup test_mysql_backup "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:Mysql/mysqlBackup:MysqlBackup")]
    public partial class MysqlBackup : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The size of the backup in base-2 (IEC) gibibytes. (GiB).
        /// </summary>
        [Output("backupSizeInGbs")]
        public Output<int> BackupSizeInGbs { get; private set; } = null!;

        /// <summary>
        /// The type of backup.
        /// </summary>
        [Output("backupType")]
        public Output<string> BackupType { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The OCID of the compartment the backup exists in.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// Indicates how the backup was created: manually, automatic, or by an Operator.
        /// </summary>
        [Output("creationType")]
        public Output<string> CreationType { get; private set; } = null!;

        /// <summary>
        /// DEPRECATED: User specified size of the data volume. May be less than current allocatedStorageSizeInGBs. Replaced by dataStorage.dataStorageSizeInGBs.
        /// </summary>
        [Output("dataStorageSizeInGb")]
        public Output<int> DataStorageSizeInGb { get; private set; } = null!;

        /// <summary>
        /// The OCID of the DB System the Backup is associated with.
        /// </summary>
        [Output("dbSystemId")]
        public Output<string> DbSystemId { get; private set; } = null!;

        [Output("dbSystemSnapshotSummaries")]
        public Output<ImmutableArray<Outputs.MysqlBackupDbSystemSnapshotSummary>> DbSystemSnapshotSummaries { get; private set; } = null!;

        /// <summary>
        /// Snapshot of the DbSystem details at the time of the backup
        /// </summary>
        [Output("dbSystemSnapshots")]
        public Output<ImmutableArray<Outputs.MysqlBackupDbSystemSnapshot>> DbSystemSnapshots { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-supplied description for the backup.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-supplied display name for the backup.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// Encrypt data details.
        /// </summary>
        [Output("encryptData")]
        public Output<Outputs.MysqlBackupEncryptData> EncryptData { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// The OCID of the immediate source DB system backup from which this DB system backup was copied.
        /// </summary>
        [Output("immediateSourceBackupId")]
        public Output<string> ImmediateSourceBackupId { get; private set; } = null!;

        /// <summary>
        /// Additional information about the current lifecycleState.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// The MySQL server version of the DB System used for backup.
        /// </summary>
        [Output("mysqlVersion")]
        public Output<string> MysqlVersion { get; private set; } = null!;

        /// <summary>
        /// The OCID of the original source DB system backup from which this DB system backup was copied.
        /// </summary>
        [Output("originalSourceBackupId")]
        public Output<string> OriginalSourceBackupId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Number of days to retain this backup.
        /// </summary>
        [Output("retentionInDays")]
        public Output<int> RetentionInDays { get; private set; } = null!;

        /// <summary>
        /// The shape of the DB System instance used for backup.
        /// </summary>
        [Output("shapeName")]
        public Output<string> ShapeName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Retains the backup to be deleted due to the retention policy in DELETE SCHEDULED state for 7 days before permanently deleting it.
        /// </summary>
        [Output("softDelete")]
        public Output<string> SoftDelete { get; private set; } = null!;

        /// <summary>
        /// Details of backup source in the cloud.
        /// </summary>
        [Output("sourceDetails")]
        public Output<Outputs.MysqlBackupSourceDetails?> SourceDetails { get; private set; } = null!;

        /// <summary>
        /// The state of the backup.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The date and time the DB system backup copy was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
        /// </summary>
        [Output("timeCopyCreated")]
        public Output<string> TimeCopyCreated { get; private set; } = null!;

        /// <summary>
        /// The time the backup record was created.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time at which the backup was updated.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a MysqlBackup resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public MysqlBackup(string name, MysqlBackupArgs? args = null, CustomResourceOptions? options = null)
            : base("oci:Mysql/mysqlBackup:MysqlBackup", name, args ?? new MysqlBackupArgs(), MakeResourceOptions(options, ""))
        {
        }

        private MysqlBackup(string name, Input<string> id, MysqlBackupState? state = null, CustomResourceOptions? options = null)
            : base("oci:Mysql/mysqlBackup:MysqlBackup", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing MysqlBackup resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static MysqlBackup Get(string name, Input<string> id, MysqlBackupState? state = null, CustomResourceOptions? options = null)
        {
            return new MysqlBackup(name, id, state, options);
        }
    }

    public sealed class MysqlBackupArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The type of backup.
        /// </summary>
        [Input("backupType")]
        public Input<string>? BackupType { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the compartment the backup exists in.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The OCID of the DB System the Backup is associated with.
        /// </summary>
        [Input("dbSystemId")]
        public Input<string>? DbSystemId { get; set; }

        [Input("dbSystemSnapshotSummaries")]
        private InputList<Inputs.MysqlBackupDbSystemSnapshotSummaryArgs>? _dbSystemSnapshotSummaries;
        public InputList<Inputs.MysqlBackupDbSystemSnapshotSummaryArgs> DbSystemSnapshotSummaries
        {
            get => _dbSystemSnapshotSummaries ?? (_dbSystemSnapshotSummaries = new InputList<Inputs.MysqlBackupDbSystemSnapshotSummaryArgs>());
            set => _dbSystemSnapshotSummaries = value;
        }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A user-supplied description for the backup.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) A user-supplied display name for the backup.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// Encrypt data details.
        /// </summary>
        [Input("encryptData")]
        public Input<Inputs.MysqlBackupEncryptDataArgs>? EncryptData { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Number of days to retain this backup.
        /// </summary>
        [Input("retentionInDays")]
        public Input<int>? RetentionInDays { get; set; }

        /// <summary>
        /// (Updatable) Retains the backup to be deleted due to the retention policy in DELETE SCHEDULED state for 7 days before permanently deleting it.
        /// </summary>
        [Input("softDelete")]
        public Input<string>? SoftDelete { get; set; }

        /// <summary>
        /// Details of backup source in the cloud.
        /// </summary>
        [Input("sourceDetails")]
        public Input<Inputs.MysqlBackupSourceDetailsArgs>? SourceDetails { get; set; }

        public MysqlBackupArgs()
        {
        }
        public static new MysqlBackupArgs Empty => new MysqlBackupArgs();
    }

    public sealed class MysqlBackupState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The size of the backup in base-2 (IEC) gibibytes. (GiB).
        /// </summary>
        [Input("backupSizeInGbs")]
        public Input<int>? BackupSizeInGbs { get; set; }

        /// <summary>
        /// The type of backup.
        /// </summary>
        [Input("backupType")]
        public Input<string>? BackupType { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the compartment the backup exists in.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// Indicates how the backup was created: manually, automatic, or by an Operator.
        /// </summary>
        [Input("creationType")]
        public Input<string>? CreationType { get; set; }

        /// <summary>
        /// DEPRECATED: User specified size of the data volume. May be less than current allocatedStorageSizeInGBs. Replaced by dataStorage.dataStorageSizeInGBs.
        /// </summary>
        [Input("dataStorageSizeInGb")]
        public Input<int>? DataStorageSizeInGb { get; set; }

        /// <summary>
        /// The OCID of the DB System the Backup is associated with.
        /// </summary>
        [Input("dbSystemId")]
        public Input<string>? DbSystemId { get; set; }

        [Input("dbSystemSnapshotSummaries")]
        private InputList<Inputs.MysqlBackupDbSystemSnapshotSummaryGetArgs>? _dbSystemSnapshotSummaries;
        public InputList<Inputs.MysqlBackupDbSystemSnapshotSummaryGetArgs> DbSystemSnapshotSummaries
        {
            get => _dbSystemSnapshotSummaries ?? (_dbSystemSnapshotSummaries = new InputList<Inputs.MysqlBackupDbSystemSnapshotSummaryGetArgs>());
            set => _dbSystemSnapshotSummaries = value;
        }

        [Input("dbSystemSnapshots")]
        private InputList<Inputs.MysqlBackupDbSystemSnapshotGetArgs>? _dbSystemSnapshots;

        /// <summary>
        /// Snapshot of the DbSystem details at the time of the backup
        /// </summary>
        public InputList<Inputs.MysqlBackupDbSystemSnapshotGetArgs> DbSystemSnapshots
        {
            get => _dbSystemSnapshots ?? (_dbSystemSnapshots = new InputList<Inputs.MysqlBackupDbSystemSnapshotGetArgs>());
            set => _dbSystemSnapshots = value;
        }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A user-supplied description for the backup.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) A user-supplied display name for the backup.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// Encrypt data details.
        /// </summary>
        [Input("encryptData")]
        public Input<Inputs.MysqlBackupEncryptDataGetArgs>? EncryptData { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// The OCID of the immediate source DB system backup from which this DB system backup was copied.
        /// </summary>
        [Input("immediateSourceBackupId")]
        public Input<string>? ImmediateSourceBackupId { get; set; }

        /// <summary>
        /// Additional information about the current lifecycleState.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// The MySQL server version of the DB System used for backup.
        /// </summary>
        [Input("mysqlVersion")]
        public Input<string>? MysqlVersion { get; set; }

        /// <summary>
        /// The OCID of the original source DB system backup from which this DB system backup was copied.
        /// </summary>
        [Input("originalSourceBackupId")]
        public Input<string>? OriginalSourceBackupId { get; set; }

        /// <summary>
        /// (Updatable) Number of days to retain this backup.
        /// </summary>
        [Input("retentionInDays")]
        public Input<int>? RetentionInDays { get; set; }

        /// <summary>
        /// The shape of the DB System instance used for backup.
        /// </summary>
        [Input("shapeName")]
        public Input<string>? ShapeName { get; set; }

        /// <summary>
        /// (Updatable) Retains the backup to be deleted due to the retention policy in DELETE SCHEDULED state for 7 days before permanently deleting it.
        /// </summary>
        [Input("softDelete")]
        public Input<string>? SoftDelete { get; set; }

        /// <summary>
        /// Details of backup source in the cloud.
        /// </summary>
        [Input("sourceDetails")]
        public Input<Inputs.MysqlBackupSourceDetailsGetArgs>? SourceDetails { get; set; }

        /// <summary>
        /// The state of the backup.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The date and time the DB system backup copy was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
        /// </summary>
        [Input("timeCopyCreated")]
        public Input<string>? TimeCopyCreated { get; set; }

        /// <summary>
        /// The time the backup record was created.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time at which the backup was updated.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public MysqlBackupState()
        {
        }
        public static new MysqlBackupState Empty => new MysqlBackupState();
    }
}
