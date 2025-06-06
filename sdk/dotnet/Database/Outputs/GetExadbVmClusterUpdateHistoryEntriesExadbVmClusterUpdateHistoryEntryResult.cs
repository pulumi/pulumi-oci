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
    public sealed class GetExadbVmClusterUpdateHistoryEntriesExadbVmClusterUpdateHistoryEntryResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the maintenance update history entry.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Descriptive text providing additional details about the lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The current lifecycle state of the maintenance update operation.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time when the maintenance update action completed.
        /// </summary>
        public readonly string TimeCompleted;
        /// <summary>
        /// The date and time when the maintenance update action started.
        /// </summary>
        public readonly string TimeStarted;
        /// <summary>
        /// The update action.
        /// </summary>
        public readonly string UpdateAction;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the maintenance update.
        /// </summary>
        public readonly string UpdateId;
        /// <summary>
        /// A filter to return only resources that match the given update type exactly.
        /// </summary>
        public readonly string UpdateType;
        /// <summary>
        /// The version of the maintenance update package.
        /// </summary>
        public readonly string Version;

        [OutputConstructor]
        private GetExadbVmClusterUpdateHistoryEntriesExadbVmClusterUpdateHistoryEntryResult(
            string id,

            string lifecycleDetails,

            string state,

            string timeCompleted,

            string timeStarted,

            string updateAction,

            string updateId,

            string updateType,

            string version)
        {
            Id = id;
            LifecycleDetails = lifecycleDetails;
            State = state;
            TimeCompleted = timeCompleted;
            TimeStarted = timeStarted;
            UpdateAction = updateAction;
            UpdateId = updateId;
            UpdateType = updateType;
            Version = version;
        }
    }
}
