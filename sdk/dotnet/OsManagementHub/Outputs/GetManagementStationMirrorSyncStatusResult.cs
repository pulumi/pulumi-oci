// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub.Outputs
{

    [OutputType]
    public sealed class GetManagementStationMirrorSyncStatusResult
    {
        /// <summary>
        /// Total of mirrors in 'failed' state
        /// </summary>
        public readonly int Failed;
        /// <summary>
        /// Total of mirrors in 'queued' state
        /// </summary>
        public readonly int Queued;
        /// <summary>
        /// Total of mirrors in 'synced' state
        /// </summary>
        public readonly int Synced;
        /// <summary>
        /// Total of mirrors in 'syncing' state
        /// </summary>
        public readonly int Syncing;
        /// <summary>
        /// Total of mirrors in 'failed' state
        /// </summary>
        public readonly int Unsynced;

        [OutputConstructor]
        private GetManagementStationMirrorSyncStatusResult(
            int failed,

            int queued,

            int synced,

            int syncing,

            int unsynced)
        {
            Failed = failed;
            Queued = queued;
            Synced = synced;
            Syncing = syncing;
            Unsynced = unsynced;
        }
    }
}