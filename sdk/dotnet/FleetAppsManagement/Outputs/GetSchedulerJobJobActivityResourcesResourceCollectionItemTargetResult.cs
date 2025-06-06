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
    public sealed class GetSchedulerJobJobActivityResourcesResourceCollectionItemTargetResult
    {
        /// <summary>
        /// Description of the Execution status. If there are any errors, this can also include a short error message.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Status of the Job at target Level.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// Unique target name
        /// </summary>
        public readonly string TargetName;

        [OutputConstructor]
        private GetSchedulerJobJobActivityResourcesResourceCollectionItemTargetResult(
            string description,

            string status,

            string targetName)
        {
            Description = description;
            Status = status;
            TargetName = targetName;
        }
    }
}
