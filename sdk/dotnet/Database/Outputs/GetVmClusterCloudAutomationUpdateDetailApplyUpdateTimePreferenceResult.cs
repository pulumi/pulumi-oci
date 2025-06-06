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
    public sealed class GetVmClusterCloudAutomationUpdateDetailApplyUpdateTimePreferenceResult
    {
        /// <summary>
        /// End time for polling VM cloud automation software updates for the cluster. If the endTime is not specified, 2 AM UTC is used by default.
        /// </summary>
        public readonly string ApplyUpdatePreferredEndTime;
        /// <summary>
        /// Start time for polling VM cloud automation software updates for the cluster. If the startTime is not specified, 12 AM UTC is used by default.
        /// </summary>
        public readonly string ApplyUpdatePreferredStartTime;

        [OutputConstructor]
        private GetVmClusterCloudAutomationUpdateDetailApplyUpdateTimePreferenceResult(
            string applyUpdatePreferredEndTime,

            string applyUpdatePreferredStartTime)
        {
            ApplyUpdatePreferredEndTime = applyUpdatePreferredEndTime;
            ApplyUpdatePreferredStartTime = applyUpdatePreferredStartTime;
        }
    }
}
