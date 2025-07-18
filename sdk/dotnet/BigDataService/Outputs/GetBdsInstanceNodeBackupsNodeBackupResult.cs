// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.BigDataService.Outputs
{

    [OutputType]
    public sealed class GetBdsInstanceNodeBackupsNodeBackupResult
    {
        /// <summary>
        /// type based on how backup action was initiated.
        /// </summary>
        public readonly string BackupTriggerType;
        /// <summary>
        /// Incremental backup type includes only the changes since the last backup. Full backup type includes all changes since the volume was created.
        /// </summary>
        public readonly string BackupType;
        /// <summary>
        /// The display name belonged to the node backup.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The id of the node backup.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The ID of the nodeBackupConfiguration if the NodeBackup is automatically created by applying the configuration.
        /// </summary>
        public readonly string NodeBackupConfigId;
        /// <summary>
        /// The node host name belonged to a node that has a node backup.
        /// </summary>
        public readonly string NodeHostName;
        /// <summary>
        /// The instance OCID of the node, which is the resource from which the node backup was acquired.
        /// </summary>
        public readonly string NodeInstanceId;
        /// <summary>
        /// The state of the Node's Backup.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The time the cluster was created, shown as an RFC 3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetBdsInstanceNodeBackupsNodeBackupResult(
            string backupTriggerType,

            string backupType,

            string displayName,

            string id,

            string nodeBackupConfigId,

            string nodeHostName,

            string nodeInstanceId,

            string state,

            string timeCreated)
        {
            BackupTriggerType = backupTriggerType;
            BackupType = backupType;
            DisplayName = displayName;
            Id = id;
            NodeBackupConfigId = nodeBackupConfigId;
            NodeHostName = nodeHostName;
            NodeInstanceId = nodeInstanceId;
            State = state;
            TimeCreated = timeCreated;
        }
    }
}
