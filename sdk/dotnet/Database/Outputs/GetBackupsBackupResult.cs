// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class GetBackupsBackupResult
    {
        /// <summary>
        /// The name of the availability domain where the database backup is stored.
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// A filter to return only resources that match the given backup destination type.
        /// </summary>
        public readonly string BackupDestinationType;
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The Oracle Database Edition that applies to all the databases on the DB system. Exadata DB systems and 2-node RAC DB systems require ENTERPRISE_EDITION_EXTREME_PERFORMANCE.
        /// </summary>
        public readonly string DatabaseEdition;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
        /// </summary>
        public readonly string DatabaseId;
        /// <summary>
        /// The size of the database in gigabytes at the time the backup was taken.
        /// </summary>
        public readonly double DatabaseSizeInGbs;
        /// <summary>
        /// The user-friendly name for the backup. The name does not have to be unique.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Types of providers supported for managing database encryption keys
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBackupsBackupEncryptionKeyLocationDetailResult> EncryptionKeyLocationDetails;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// True if Oracle Managed Keys is required for restore of the backup.
        /// </summary>
        public readonly bool IsUsingOracleManagedKeys;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store of Oracle Vault.
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
        /// The OCID of the key container version that is used in database transparent data encryption (TDE) operations KMS Key can have multiple key versions. If none is specified, the current key version (latest) of the Key Id is used for the operation. Autonomous Database Serverless does not use key versions, hence is not applicable for Autonomous Database Serverless instances.
        /// </summary>
        public readonly string KmsKeyVersionId;
        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The retention period of the long term backup in days.
        /// </summary>
        public readonly int RetentionPeriodInDays;
        /// <summary>
        /// The retention period of the long term backup in years.
        /// </summary>
        public readonly int RetentionPeriodInYears;
        /// <summary>
        /// List of OCIDs of the key containers used as the secondary encryption key in database transparent data encryption (TDE) operations.
        /// </summary>
        public readonly ImmutableArray<string> SecondaryKmsKeyIds;
        /// <summary>
        /// Shape of the backup's source database.
        /// </summary>
        public readonly string Shape;
        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the backup was completed.
        /// </summary>
        public readonly string TimeEnded;
        /// <summary>
        /// Expiration time of the long term database backup.
        /// </summary>
        public readonly string TimeExpiryScheduled;
        /// <summary>
        /// The date and time the backup started.
        /// </summary>
        public readonly string TimeStarted;
        /// <summary>
        /// A filter to return only backups that matches with the given type of Backup.
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts). This parameter and `secretId` are required for Customer Managed Keys.
        /// </summary>
        public readonly string VaultId;
        /// <summary>
        /// A filter to return only resources that match the given database version.
        /// </summary>
        public readonly string Version;

        [OutputConstructor]
        private GetBackupsBackupResult(
            string availabilityDomain,

            string backupDestinationType,

            string compartmentId,

            string databaseEdition,

            string databaseId,

            double databaseSizeInGbs,

            string displayName,

            ImmutableArray<Outputs.GetBackupsBackupEncryptionKeyLocationDetailResult> encryptionKeyLocationDetails,

            string id,

            bool isUsingOracleManagedKeys,

            string keyStoreId,

            string keyStoreWalletName,

            string kmsKeyId,

            string kmsKeyVersionId,

            string lifecycleDetails,

            int retentionPeriodInDays,

            int retentionPeriodInYears,

            ImmutableArray<string> secondaryKmsKeyIds,

            string shape,

            string state,

            string timeEnded,

            string timeExpiryScheduled,

            string timeStarted,

            string type,

            string vaultId,

            string version)
        {
            AvailabilityDomain = availabilityDomain;
            BackupDestinationType = backupDestinationType;
            CompartmentId = compartmentId;
            DatabaseEdition = databaseEdition;
            DatabaseId = databaseId;
            DatabaseSizeInGbs = databaseSizeInGbs;
            DisplayName = displayName;
            EncryptionKeyLocationDetails = encryptionKeyLocationDetails;
            Id = id;
            IsUsingOracleManagedKeys = isUsingOracleManagedKeys;
            KeyStoreId = keyStoreId;
            KeyStoreWalletName = keyStoreWalletName;
            KmsKeyId = kmsKeyId;
            KmsKeyVersionId = kmsKeyVersionId;
            LifecycleDetails = lifecycleDetails;
            RetentionPeriodInDays = retentionPeriodInDays;
            RetentionPeriodInYears = retentionPeriodInYears;
            SecondaryKmsKeyIds = secondaryKmsKeyIds;
            Shape = shape;
            State = state;
            TimeEnded = timeEnded;
            TimeExpiryScheduled = timeExpiryScheduled;
            TimeStarted = timeStarted;
            Type = type;
            VaultId = vaultId;
            Version = version;
        }
    }
}
