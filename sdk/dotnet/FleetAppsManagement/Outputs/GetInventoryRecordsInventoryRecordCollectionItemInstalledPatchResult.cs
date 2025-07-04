// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Outputs
{

    [OutputType]
    public sealed class GetInventoryRecordsInventoryRecordCollectionItemInstalledPatchResult
    {
        /// <summary>
        /// Description for the installed patch
        /// </summary>
        public readonly string PatchDescription;
        /// <summary>
        /// OCID of the installed patch
        /// </summary>
        public readonly string PatchId;
        /// <summary>
        /// Name of the installed patch
        /// </summary>
        public readonly string PatchName;
        /// <summary>
        /// Type of patch applied
        /// </summary>
        public readonly string PatchType;
        /// <summary>
        /// Date on which the patch was applied to the target
        /// </summary>
        public readonly string TimeApplied;

        [OutputConstructor]
        private GetInventoryRecordsInventoryRecordCollectionItemInstalledPatchResult(
            string patchDescription,

            string patchId,

            string patchName,

            string patchType,

            string timeApplied)
        {
            PatchDescription = patchDescription;
            PatchId = patchId;
            PatchName = patchName;
            PatchType = patchType;
            TimeApplied = timeApplied;
        }
    }
}
