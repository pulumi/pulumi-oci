// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    /// <summary>
    /// This resource provides the Database resource in Oracle Cloud Infrastructure Database service.
    /// 
    /// Creates a new database in the specified Database Home. If the database version is provided, it must match the version of the Database Home. Applies only to Exadata systems.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// class MyStack : Stack
    /// {
    ///     public MyStack()
    ///     {
    ///         var testDatabase = new Oci.Database.Database("testDatabase", new Oci.Database.DatabaseArgs
    ///         {
    ///             Database = new Oci.Database.Inputs.DatabaseDatabaseArgs
    ///             {
    ///                 AdminPassword = @var.Database_database_admin_password,
    ///                 DbName = @var.Database_database_db_name,
    ///                 BackupId = oci_database_backup.Test_backup.Id,
    ///                 BackupTdePassword = @var.Database_database_backup_tde_password,
    ///                 CharacterSet = @var.Database_database_character_set,
    ///                 DatabaseSoftwareImageId = oci_database_database_software_image.Test_database_software_image.Id,
    ///                 DbBackupConfig = new Oci.Database.Inputs.DatabaseDatabaseDbBackupConfigArgs
    ///                 {
    ///                     AutoBackupEnabled = @var.Database_database_db_backup_config_auto_backup_enabled,
    ///                     AutoBackupWindow = @var.Database_database_db_backup_config_auto_backup_window,
    ///                     BackupDestinationDetails = 
    ///                     {
    ///                         new Oci.Database.Inputs.DatabaseDatabaseDbBackupConfigBackupDestinationDetailArgs
    ///                         {
    ///                             Id = @var.Database_database_db_backup_config_backup_destination_details_id,
    ///                             Type = @var.Database_database_db_backup_config_backup_destination_details_type,
    ///                         },
    ///                     },
    ///                     RecoveryWindowInDays = @var.Database_database_db_backup_config_recovery_window_in_days,
    ///                 },
    ///                 DbUniqueName = @var.Database_database_db_unique_name,
    ///                 DbWorkload = @var.Database_database_db_workload,
    ///                 DefinedTags = @var.Database_database_defined_tags,
    ///                 FreeformTags = @var.Database_database_freeform_tags,
    ///                 KmsKeyId = oci_kms_key.Test_key.Id,
    ///                 KmsKeyVersionId = oci_kms_key_version.Test_key_version.Id,
    ///                 NcharacterSet = @var.Database_database_ncharacter_set,
    ///                 PdbName = @var.Database_database_pdb_name,
    ///                 SidPrefix = @var.Database_database_sid_prefix,
    ///                 TdeWalletPassword = @var.Database_database_tde_wallet_password,
    ///                 VaultId = oci_kms_vault.Test_vault.Id,
    ///             },
    ///             DbHomeId = oci_database_db_home.Test_db_home.Id,
    ///             Source = @var.Database_source,
    ///             DbVersion = @var.Database_db_version,
    ///             KmsKeyId = oci_kms_key.Test_key.Id,
    ///             KmsKeyVersionId = oci_kms_key_version.Test_key_version.Id,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// Databases can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:Database/database:Database test_database "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:Database/database:Database")]
    public partial class Database : Pulumi.CustomResource
    {
        /// <summary>
        /// The character set for the database.  The default is AL32UTF8. Allowed values are:
        /// </summary>
        [Output("characterSet")]
        public Output<string> CharacterSet { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// The Connection strings used to connect to the Oracle Database.
        /// </summary>
        [Output("connectionStrings")]
        public Output<ImmutableArray<Outputs.DatabaseConnectionString>> ConnectionStrings { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Details for creating a database.
        /// </summary>
        [Output("database")]
        public Output<Outputs.DatabaseDatabase> DatabaseName { get; private set; } = null!;

        /// <summary>
        /// The configuration of the Database Management service.
        /// </summary>
        [Output("databaseManagementConfigs")]
        public Output<ImmutableArray<Outputs.DatabaseDatabaseManagementConfig>> DatabaseManagementConfigs { get; private set; } = null!;

        /// <summary>
        /// The database software image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
        /// </summary>
        [Output("databaseSoftwareImageId")]
        public Output<string> DatabaseSoftwareImageId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Backup Options To use any of the API operations, you must be authorized in an IAM policy. If you're not authorized, talk to an administrator. If you're an administrator who needs to write policies to give users access, see [Getting Started with Policies](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policygetstarted.htm).
        /// </summary>
        [Output("dbBackupConfigs")]
        public Output<ImmutableArray<Outputs.DatabaseDbBackupConfig>> DbBackupConfigs { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
        /// </summary>
        [Output("dbHomeId")]
        public Output<string> DbHomeId { get; private set; } = null!;

        /// <summary>
        /// The display name of the database to be created from the backup. It must begin with an alphabetic character and can contain a maximum of eight alphanumeric characters. Special characters are not permitted.
        /// </summary>
        [Output("dbName")]
        public Output<string> DbName { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
        /// </summary>
        [Output("dbSystemId")]
        public Output<string> DbSystemId { get; private set; } = null!;

        /// <summary>
        /// The `DB_UNIQUE_NAME` of the Oracle Database being backed up.
        /// </summary>
        [Output("dbUniqueName")]
        public Output<string> DbUniqueName { get; private set; } = null!;

        /// <summary>
        /// A valid Oracle Database version. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
        /// </summary>
        [Output("dbVersion")]
        public Output<string> DbVersion { get; private set; } = null!;

        /// <summary>
        /// The database workload type.
        /// </summary>
        [Output("dbWorkload")]
        public Output<string> DbWorkload { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// True if the database is a container database.
        /// </summary>
        [Output("isCdb")]
        public Output<bool> IsCdb { get; private set; } = null!;

        /// <summary>
        /// The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
        /// </summary>
        [Output("kmsKeyId")]
        public Output<string> KmsKeyId { get; private set; } = null!;

        /// <summary>
        /// The value to migrate to the kms version from none. Can only use once by setting value to true. You can not switch back to non-kms once you created or migrated.(https://www.oracle.com/security/cloud-security/key-management/faq/)
        /// </summary>
        [Output("kmsKeyMigration")]
        public Output<bool?> KmsKeyMigration { get; private set; } = null!;

        /// <summary>
        /// The value to rotate the key version of current kms_key. Just change this value will trigger the rotation.
        /// </summary>
        [Output("kmsKeyRotation")]
        public Output<int?> KmsKeyRotation { get; private set; } = null!;

        /// <summary>
        /// The OCID of the key container version that is used in database transparent data encryption (TDE) operations KMS Key can have multiple key versions. If none is specified, the current key version (latest) of the Key Id is used for the operation.
        /// </summary>
        [Output("kmsKeyVersionId")]
        public Output<string> KmsKeyVersionId { get; private set; } = null!;

        /// <summary>
        /// The date and time when the latest database backup was created.
        /// </summary>
        [Output("lastBackupTimestamp")]
        public Output<string> LastBackupTimestamp { get; private set; } = null!;

        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// The national character set for the database.  The default is AL16UTF16. Allowed values are: AL16UTF16 or UTF8.
        /// </summary>
        [Output("ncharacterSet")]
        public Output<string> NcharacterSet { get; private set; } = null!;

        /// <summary>
        /// The name of the pluggable database. The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. Pluggable database should not be same as database name.
        /// </summary>
        [Output("pdbName")]
        public Output<string> PdbName { get; private set; } = null!;

        /// <summary>
        /// Specifies a prefix for the `Oracle SID` of the database to be created.
        /// </summary>
        [Output("sidPrefix")]
        public Output<string> SidPrefix { get; private set; } = null!;

        /// <summary>
        /// The source of the database: Use `NONE` for creating a new database. Use `DB_BACKUP` for creating a new database by restoring from a backup. The default is `NONE`.
        /// </summary>
        [Output("source")]
        public Output<string> Source { get; private set; } = null!;

        /// <summary>
        /// Point in time recovery timeStamp of the source database at which cloned database system is cloned from the source database system, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339)
        /// </summary>
        [Output("sourceDatabasePointInTimeRecoveryTimestamp")]
        public Output<string> SourceDatabasePointInTimeRecoveryTimestamp { get; private set; } = null!;

        /// <summary>
        /// The current state of the database.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The date and time the database was created.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
        /// </summary>
        [Output("vaultId")]
        public Output<string> VaultId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
        /// </summary>
        [Output("vmClusterId")]
        public Output<string> VmClusterId { get; private set; } = null!;


        /// <summary>
        /// Create a Database resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Database(string name, DatabaseArgs args, CustomResourceOptions? options = null)
            : base("oci:Database/database:Database", name, args ?? new DatabaseArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Database(string name, Input<string> id, DatabaseState? state = null, CustomResourceOptions? options = null)
            : base("oci:Database/database:Database", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing Database resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Database Get(string name, Input<string> id, DatabaseState? state = null, CustomResourceOptions? options = null)
        {
            return new Database(name, id, state, options);
        }
    }

    public sealed class DatabaseArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Details for creating a database.
        /// </summary>
        [Input("database", required: true)]
        public Input<Inputs.DatabaseDatabaseArgs> DatabaseName { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
        /// </summary>
        [Input("dbHomeId", required: true)]
        public Input<string> DbHomeId { get; set; } = null!;

        /// <summary>
        /// A valid Oracle Database version. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
        /// </summary>
        [Input("dbVersion")]
        public Input<string>? DbVersion { get; set; }

        /// <summary>
        /// The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
        /// </summary>
        [Input("kmsKeyId")]
        public Input<string>? KmsKeyId { get; set; }

        /// <summary>
        /// The value to migrate to the kms version from none. Can only use once by setting value to true. You can not switch back to non-kms once you created or migrated.(https://www.oracle.com/security/cloud-security/key-management/faq/)
        /// </summary>
        [Input("kmsKeyMigration")]
        public Input<bool>? KmsKeyMigration { get; set; }

        /// <summary>
        /// The value to rotate the key version of current kms_key. Just change this value will trigger the rotation.
        /// </summary>
        [Input("kmsKeyRotation")]
        public Input<int>? KmsKeyRotation { get; set; }

        /// <summary>
        /// The OCID of the key container version that is used in database transparent data encryption (TDE) operations KMS Key can have multiple key versions. If none is specified, the current key version (latest) of the Key Id is used for the operation.
        /// </summary>
        [Input("kmsKeyVersionId")]
        public Input<string>? KmsKeyVersionId { get; set; }

        /// <summary>
        /// The source of the database: Use `NONE` for creating a new database. Use `DB_BACKUP` for creating a new database by restoring from a backup. The default is `NONE`.
        /// </summary>
        [Input("source", required: true)]
        public Input<string> Source { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
        /// </summary>
        [Input("vaultId")]
        public Input<string>? VaultId { get; set; }

        public DatabaseArgs()
        {
        }
    }

    public sealed class DatabaseState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The character set for the database.  The default is AL32UTF8. Allowed values are:
        /// </summary>
        [Input("characterSet")]
        public Input<string>? CharacterSet { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("connectionStrings")]
        private InputList<Inputs.DatabaseConnectionStringGetArgs>? _connectionStrings;

        /// <summary>
        /// The Connection strings used to connect to the Oracle Database.
        /// </summary>
        public InputList<Inputs.DatabaseConnectionStringGetArgs> ConnectionStrings
        {
            get => _connectionStrings ?? (_connectionStrings = new InputList<Inputs.DatabaseConnectionStringGetArgs>());
            set => _connectionStrings = value;
        }

        /// <summary>
        /// (Updatable) Details for creating a database.
        /// </summary>
        [Input("database")]
        public Input<Inputs.DatabaseDatabaseGetArgs>? DatabaseName { get; set; }

        [Input("databaseManagementConfigs")]
        private InputList<Inputs.DatabaseDatabaseManagementConfigGetArgs>? _databaseManagementConfigs;

        /// <summary>
        /// The configuration of the Database Management service.
        /// </summary>
        public InputList<Inputs.DatabaseDatabaseManagementConfigGetArgs> DatabaseManagementConfigs
        {
            get => _databaseManagementConfigs ?? (_databaseManagementConfigs = new InputList<Inputs.DatabaseDatabaseManagementConfigGetArgs>());
            set => _databaseManagementConfigs = value;
        }

        /// <summary>
        /// The database software image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
        /// </summary>
        [Input("databaseSoftwareImageId")]
        public Input<string>? DatabaseSoftwareImageId { get; set; }

        [Input("dbBackupConfigs")]
        private InputList<Inputs.DatabaseDbBackupConfigGetArgs>? _dbBackupConfigs;

        /// <summary>
        /// (Updatable) Backup Options To use any of the API operations, you must be authorized in an IAM policy. If you're not authorized, talk to an administrator. If you're an administrator who needs to write policies to give users access, see [Getting Started with Policies](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policygetstarted.htm).
        /// </summary>
        public InputList<Inputs.DatabaseDbBackupConfigGetArgs> DbBackupConfigs
        {
            get => _dbBackupConfigs ?? (_dbBackupConfigs = new InputList<Inputs.DatabaseDbBackupConfigGetArgs>());
            set => _dbBackupConfigs = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
        /// </summary>
        [Input("dbHomeId")]
        public Input<string>? DbHomeId { get; set; }

        /// <summary>
        /// The display name of the database to be created from the backup. It must begin with an alphabetic character and can contain a maximum of eight alphanumeric characters. Special characters are not permitted.
        /// </summary>
        [Input("dbName")]
        public Input<string>? DbName { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
        /// </summary>
        [Input("dbSystemId")]
        public Input<string>? DbSystemId { get; set; }

        /// <summary>
        /// The `DB_UNIQUE_NAME` of the Oracle Database being backed up.
        /// </summary>
        [Input("dbUniqueName")]
        public Input<string>? DbUniqueName { get; set; }

        /// <summary>
        /// A valid Oracle Database version. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
        /// </summary>
        [Input("dbVersion")]
        public Input<string>? DbVersion { get; set; }

        /// <summary>
        /// The database workload type.
        /// </summary>
        [Input("dbWorkload")]
        public Input<string>? DbWorkload { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// True if the database is a container database.
        /// </summary>
        [Input("isCdb")]
        public Input<bool>? IsCdb { get; set; }

        /// <summary>
        /// The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
        /// </summary>
        [Input("kmsKeyId")]
        public Input<string>? KmsKeyId { get; set; }

        /// <summary>
        /// The value to migrate to the kms version from none. Can only use once by setting value to true. You can not switch back to non-kms once you created or migrated.(https://www.oracle.com/security/cloud-security/key-management/faq/)
        /// </summary>
        [Input("kmsKeyMigration")]
        public Input<bool>? KmsKeyMigration { get; set; }

        /// <summary>
        /// The value to rotate the key version of current kms_key. Just change this value will trigger the rotation.
        /// </summary>
        [Input("kmsKeyRotation")]
        public Input<int>? KmsKeyRotation { get; set; }

        /// <summary>
        /// The OCID of the key container version that is used in database transparent data encryption (TDE) operations KMS Key can have multiple key versions. If none is specified, the current key version (latest) of the Key Id is used for the operation.
        /// </summary>
        [Input("kmsKeyVersionId")]
        public Input<string>? KmsKeyVersionId { get; set; }

        /// <summary>
        /// The date and time when the latest database backup was created.
        /// </summary>
        [Input("lastBackupTimestamp")]
        public Input<string>? LastBackupTimestamp { get; set; }

        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// The national character set for the database.  The default is AL16UTF16. Allowed values are: AL16UTF16 or UTF8.
        /// </summary>
        [Input("ncharacterSet")]
        public Input<string>? NcharacterSet { get; set; }

        /// <summary>
        /// The name of the pluggable database. The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. Pluggable database should not be same as database name.
        /// </summary>
        [Input("pdbName")]
        public Input<string>? PdbName { get; set; }

        /// <summary>
        /// Specifies a prefix for the `Oracle SID` of the database to be created.
        /// </summary>
        [Input("sidPrefix")]
        public Input<string>? SidPrefix { get; set; }

        /// <summary>
        /// The source of the database: Use `NONE` for creating a new database. Use `DB_BACKUP` for creating a new database by restoring from a backup. The default is `NONE`.
        /// </summary>
        [Input("source")]
        public Input<string>? Source { get; set; }

        /// <summary>
        /// Point in time recovery timeStamp of the source database at which cloned database system is cloned from the source database system, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339)
        /// </summary>
        [Input("sourceDatabasePointInTimeRecoveryTimestamp")]
        public Input<string>? SourceDatabasePointInTimeRecoveryTimestamp { get; set; }

        /// <summary>
        /// The current state of the database.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The date and time the database was created.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
        /// </summary>
        [Input("vaultId")]
        public Input<string>? VaultId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
        /// </summary>
        [Input("vmClusterId")]
        public Input<string>? VmClusterId { get; set; }

        public DatabaseState()
        {
        }
    }
}
