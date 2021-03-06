// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GoldenGate.Outputs
{

    [OutputType]
    public sealed class GetDeploymentBackupsDeploymentBackupCollectionItemResult
    {
        /// <summary>
        /// Possible Deployment backup types.
        /// </summary>
        public readonly string BackupType;
        /// <summary>
        /// Name of the bucket where the object is to be uploaded in the object storage
        /// </summary>
        public readonly string Bucket;
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Tags defined for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The ID of the deployment in which to list resources.
        /// </summary>
        public readonly string DeploymentId;
        /// <summary>
        /// A filter to return only the resources that match the entire 'displayName' given.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// A simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup being referenced.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// True if this object is automatically created
        /// </summary>
        public readonly bool IsAutomatic;
        /// <summary>
        /// Describes the object's current state in detail. For example, it can be used to provide actionable information for a resource in a Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Name of namespace that serves as a container for all of your buckets
        /// </summary>
        public readonly string Namespace;
        /// <summary>
        /// Name of the object to be uploaded to object storage
        /// </summary>
        public readonly string Object;
        /// <summary>
        /// Version of OGG
        /// </summary>
        public readonly string OggVersion;
        /// <summary>
        /// The size of the backup stored in object storage (in bytes)
        /// </summary>
        public readonly double SizeInBytes;
        /// <summary>
        /// A filter to return only the resources that match the 'lifecycleState' given.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// The time of the resource backup finish. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        /// </summary>
        public readonly string TimeBackupFinished;
        /// <summary>
        /// The time the resource was created. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time of the resource backup. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        /// </summary>
        public readonly string TimeOfBackup;
        /// <summary>
        /// The time the resource was last updated. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetDeploymentBackupsDeploymentBackupCollectionItemResult(
            string backupType,

            string bucket,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string deploymentId,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            bool isAutomatic,

            string lifecycleDetails,

            string @namespace,

            string @object,

            string oggVersion,

            double sizeInBytes,

            string state,

            ImmutableDictionary<string, object> systemTags,

            string timeBackupFinished,

            string timeCreated,

            string timeOfBackup,

            string timeUpdated)
        {
            BackupType = backupType;
            Bucket = bucket;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DeploymentId = deploymentId;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            IsAutomatic = isAutomatic;
            LifecycleDetails = lifecycleDetails;
            Namespace = @namespace;
            Object = @object;
            OggVersion = oggVersion;
            SizeInBytes = sizeInBytes;
            State = state;
            SystemTags = systemTags;
            TimeBackupFinished = timeBackupFinished;
            TimeCreated = timeCreated;
            TimeOfBackup = timeOfBackup;
            TimeUpdated = timeUpdated;
        }
    }
}
