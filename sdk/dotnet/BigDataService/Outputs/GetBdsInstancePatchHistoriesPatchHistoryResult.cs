// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.BigDataService.Outputs
{

    [OutputType]
    public sealed class GetBdsInstancePatchHistoriesPatchHistoryResult
    {
        /// <summary>
        /// The status of the patch.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The time when the patch history was last updated.
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// The version of the patch.
        /// </summary>
        public readonly string Version;

        [OutputConstructor]
        private GetBdsInstancePatchHistoriesPatchHistoryResult(
            string state,

            string timeUpdated,

            string version)
        {
            State = state;
            TimeUpdated = timeUpdated;
            Version = version;
        }
    }
}