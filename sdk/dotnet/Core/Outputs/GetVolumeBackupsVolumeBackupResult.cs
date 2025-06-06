// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetVolumeBackupsVolumeBackupResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The date and time the volume backup will expire and be automatically deleted. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). This parameter will always be present for backups that were created automatically by a scheduled-backup policy. For manually created backups, it will be absent, signifying that there is no expiration time and the backup will last forever until manually deleted.
        /// </summary>
        public readonly string ExpirationTime;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The OCID of the volume backup.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The OCID of the Vault service key which is the master encryption key for the volume backup. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
        /// </summary>
        public readonly string KmsKeyId;
        /// <summary>
        /// The size of the volume, in GBs.
        /// </summary>
        public readonly string SizeInGbs;
        /// <summary>
        /// The size of the volume in MBs. The value must be a multiple of 1024. This field is deprecated. Please use `size_in_gbs`.
        /// </summary>
        public readonly string SizeInMbs;
        public readonly ImmutableArray<Outputs.GetVolumeBackupsVolumeBackupSourceDetailResult> SourceDetails;
        /// <summary>
        /// Specifies whether the backup was created manually, or via scheduled backup policy.
        /// </summary>
        public readonly string SourceType;
        /// <summary>
        /// A filter to return only resources that originated from the given source volume backup.
        /// </summary>
        public readonly string SourceVolumeBackupId;
        /// <summary>
        /// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The date and time the volume backup was created. This is the time the actual point-in-time image of the volume data was taken. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the request to create the volume backup was received. Format defined by [RFC3339]https://tools.ietf.org/html/rfc3339.
        /// </summary>
        public readonly string TimeRequestReceived;
        /// <summary>
        /// The type of a volume backup. Supported values are 'FULL' or 'INCREMENTAL'.
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// The size used by the backup, in GBs. It is typically smaller than sizeInGBs, depending on the space consumed on the volume and whether the backup is full or incremental.
        /// </summary>
        public readonly string UniqueSizeInGbs;
        /// <summary>
        /// The size used by the backup, in MBs. It is typically smaller than sizeInMBs, depending on the space consumed on the volume and whether the backup is full or incremental. This field is deprecated. Please use uniqueSizeInGBs.
        /// </summary>
        public readonly string UniqueSizeInMbs;
        /// <summary>
        /// The OCID of the volume.
        /// </summary>
        public readonly string VolumeId;

        [OutputConstructor]
        private GetVolumeBackupsVolumeBackupResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            string expirationTime,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string kmsKeyId,

            string sizeInGbs,

            string sizeInMbs,

            ImmutableArray<Outputs.GetVolumeBackupsVolumeBackupSourceDetailResult> sourceDetails,

            string sourceType,

            string sourceVolumeBackupId,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeRequestReceived,

            string type,

            string uniqueSizeInGbs,

            string uniqueSizeInMbs,

            string volumeId)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            ExpirationTime = expirationTime;
            FreeformTags = freeformTags;
            Id = id;
            KmsKeyId = kmsKeyId;
            SizeInGbs = sizeInGbs;
            SizeInMbs = sizeInMbs;
            SourceDetails = sourceDetails;
            SourceType = sourceType;
            SourceVolumeBackupId = sourceVolumeBackupId;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeRequestReceived = timeRequestReceived;
            Type = type;
            UniqueSizeInGbs = uniqueSizeInGbs;
            UniqueSizeInMbs = uniqueSizeInMbs;
            VolumeId = volumeId;
        }
    }
}
