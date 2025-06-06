// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class DbHomeDatabaseGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("adminPassword", required: true)]
        private Input<string>? _adminPassword;

        /// <summary>
        /// A strong password for SYS, SYSTEM, PDB Admin and TDE Wallet. The password must be at least nine characters and contain at least two uppercase, two lowercase, two numbers, and two special characters. The special characters must be _, \#, or -.
        /// </summary>
        public Input<string>? AdminPassword
        {
            get => _adminPassword;
            set
            {
                var emptySecret = Output.CreateSecret(0);
                _adminPassword = Output.Tuple<Input<string>?, int>(value, emptySecret).Apply(t => t.Item1);
            }
        }

        /// <summary>
        /// The backup [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("backupId")]
        public Input<string>? BackupId { get; set; }

        [Input("backupTdePassword")]
        private Input<string>? _backupTdePassword;

        /// <summary>
        /// The password to open the TDE wallet.
        /// </summary>
        public Input<string>? BackupTdePassword
        {
            get => _backupTdePassword;
            set
            {
                var emptySecret = Output.CreateSecret(0);
                _backupTdePassword = Output.Tuple<Input<string>?, int>(value, emptySecret).Apply(t => t.Item1);
            }
        }

        /// <summary>
        /// The character set for the database.  The default is AL32UTF8. Allowed values are:
        /// 
        /// AL32UTF8, AR8ADOS710, AR8ADOS720, AR8APTEC715, AR8ARABICMACS, AR8ASMO8X, AR8ISO8859P6, AR8MSWIN1256, AR8MUSSAD768, AR8NAFITHA711, AR8NAFITHA721, AR8SAKHR706, AR8SAKHR707, AZ8ISO8859P9E, BG8MSWIN, BG8PC437S, BLT8CP921, BLT8ISO8859P13, BLT8MSWIN1257, BLT8PC775, BN8BSCII, CDN8PC863, CEL8ISO8859P14, CL8ISO8859P5, CL8ISOIR111, CL8KOI8R, CL8KOI8U, CL8MACCYRILLICS, CL8MSWIN1251, EE8ISO8859P2, EE8MACCES, EE8MACCROATIANS, EE8MSWIN1250, EE8PC852, EL8DEC, EL8ISO8859P7, EL8MACGREEKS, EL8MSWIN1253, EL8PC437S, EL8PC851, EL8PC869, ET8MSWIN923, HU8ABMOD, HU8CWI2, IN8ISCII, IS8PC861, IW8ISO8859P8, IW8MACHEBREWS, IW8MSWIN1255, IW8PC1507, JA16EUC, JA16EUCTILDE, JA16SJIS, JA16SJISTILDE, JA16VMS, KO16KSC5601, KO16KSCCS, KO16MSWIN949, LA8ISO6937, LA8PASSPORT, LT8MSWIN921, LT8PC772, LT8PC774, LV8PC1117, LV8PC8LR, LV8RST104090, N8PC865, NE8ISO8859P10, NEE8ISO8859P4, RU8BESTA, RU8PC855, RU8PC866, SE8ISO8859P3, TH8MACTHAIS, TH8TISASCII, TR8DEC, TR8MACTURKISHS, TR8MSWIN1254, TR8PC857, US7ASCII, US8PC437, UTF8, VN8MSWIN1258, VN8VN3, WE8DEC, WE8DG, WE8ISO8859P1, WE8ISO8859P15, WE8ISO8859P9, WE8MACROMAN8S, WE8MSWIN1252, WE8NCR4970, WE8NEXTSTEP, WE8PC850, WE8PC858, WE8PC860, WE8ROMAN8, ZHS16CGB231280, ZHS16GBK, ZHT16BIG5, ZHT16CCDC, ZHT16DBT, ZHT16HKSCS, ZHT16MSWIN950, ZHT32EUC, ZHT32SOPS, ZHT32TRIS
        /// </summary>
        [Input("characterSet")]
        public Input<string>? CharacterSet { get; set; }

        [Input("connectionStrings")]
        private InputList<Inputs.DbHomeDatabaseConnectionStringGetArgs>? _connectionStrings;
        public InputList<Inputs.DbHomeDatabaseConnectionStringGetArgs> ConnectionStrings
        {
            get => _connectionStrings ?? (_connectionStrings = new InputList<Inputs.DbHomeDatabaseConnectionStringGetArgs>());
            set => _connectionStrings = value;
        }

        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("databaseId")]
        public Input<string>? DatabaseId { get; set; }

        /// <summary>
        /// The database software image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
        /// </summary>
        [Input("databaseSoftwareImageId")]
        public Input<string>? DatabaseSoftwareImageId { get; set; }

        /// <summary>
        /// (Updatable) Backup Options To use any of the API operations, you must be authorized in an IAM policy. If you're not authorized, talk to an administrator. If you're an administrator who needs to write policies to give users access, see [Getting Started with Policies](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policygetstarted.htm).
        /// </summary>
        [Input("dbBackupConfig")]
        public Input<Inputs.DbHomeDatabaseDbBackupConfigGetArgs>? DbBackupConfig { get; set; }

        /// <summary>
        /// The display name of the database to be created from the backup. It must begin with an alphabetic character and can contain a maximum of eight alphanumeric characters. Special characters are not permitted.
        /// </summary>
        [Input("dbName")]
        public Input<string>? DbName { get; set; }

        [Input("dbUniqueName")]
        public Input<string>? DbUniqueName { get; set; }

        /// <summary>
        /// **Deprecated.** The dbWorkload field has been deprecated for Exadata Database Service on Dedicated Infrastructure, Exadata Database Service on Cloud@Customer, and Base Database Service. Support for this attribute will end in November 2023. You may choose to update your custom scripts to exclude the dbWorkload attribute. After November 2023 if you pass a value to the dbWorkload attribute, it will be ignored.
        /// 
        /// The database workload type.
        /// </summary>
        [Input("dbWorkload")]
        public Input<string>? DbWorkload { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// Types of providers supported for managing database encryption keys
        /// </summary>
        [Input("encryptionKeyLocationDetails")]
        public Input<Inputs.DbHomeDatabaseEncryptionKeyLocationDetailsGetArgs>? EncryptionKeyLocationDetails { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store of Oracle Vault.
        /// </summary>
        [Input("keyStoreId")]
        public Input<string>? KeyStoreId { get; set; }

        /// <summary>
        /// The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
        /// </summary>
        [Input("kmsKeyId")]
        public Input<string>? KmsKeyId { get; set; }

        /// <summary>
        /// The OCID of the key container version that is used in database transparent data encryption (TDE) operations KMS Key can have multiple key versions. If none is specified, the current key version (latest) of the Key Id is used for the operation. Autonomous Database Serverless does not use key versions, hence is not applicable for Autonomous Database Serverless instances.
        /// </summary>
        [Input("kmsKeyVersionId")]
        public Input<string>? KmsKeyVersionId { get; set; }

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

        [Input("oneOffPatches")]
        private InputList<string>? _oneOffPatches;

        /// <summary>
        /// List of one-off patches for Database Homes.
        /// </summary>
        public InputList<string> OneOffPatches
        {
            get => _oneOffPatches ?? (_oneOffPatches = new InputList<string>());
            set => _oneOffPatches = value;
        }

        /// <summary>
        /// The name of the pluggable database. The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. Pluggable database should not be same as database name.
        /// </summary>
        [Input("pdbName")]
        public Input<string>? PdbName { get; set; }

        [Input("pluggableDatabases")]
        private InputList<string>? _pluggableDatabases;

        /// <summary>
        /// The list of pluggable databases that needs to be restored into new database.
        /// </summary>
        public InputList<string> PluggableDatabases
        {
            get => _pluggableDatabases ?? (_pluggableDatabases = new InputList<string>());
            set => _pluggableDatabases = value;
        }

        /// <summary>
        /// Specifies a prefix for the `Oracle SID` of the database to be created.
        /// </summary>
        [Input("sidPrefix")]
        public Input<string>? SidPrefix { get; set; }

        /// <summary>
        /// The current state of the Database Home.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("tdeWalletPassword")]
        private Input<string>? _tdeWalletPassword;

        /// <summary>
        /// The optional password to open the TDE wallet. The password must be at least nine characters and contain at least two uppercase, two lowercase, two numeric, and two special characters. The special characters must be _, \#, or -.
        /// </summary>
        public Input<string>? TdeWalletPassword
        {
            get => _tdeWalletPassword;
            set
            {
                var emptySecret = Output.CreateSecret(0);
                _tdeWalletPassword = Output.Tuple<Input<string>?, int>(value, emptySecret).Apply(t => t.Item1);
            }
        }

        /// <summary>
        /// The date and time the Database Home was created.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The point in time of the original database from which the new database is created. If not specifed, the latest backup is used to create the database.
        /// </summary>
        [Input("timeStampForPointInTimeRecovery")]
        public Input<string>? TimeStampForPointInTimeRecovery { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts). This parameter and `secretId` are required for Customer Managed Keys.
        /// </summary>
        [Input("vaultId")]
        public Input<string>? VaultId { get; set; }

        public DbHomeDatabaseGetArgs()
        {
        }
        public static new DbHomeDatabaseGetArgs Empty => new DbHomeDatabaseGetArgs();
    }
}
