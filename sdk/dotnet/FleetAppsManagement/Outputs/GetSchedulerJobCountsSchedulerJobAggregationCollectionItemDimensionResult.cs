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
    public sealed class GetSchedulerJobCountsSchedulerJobAggregationCollectionItemDimensionResult
    {
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;

        [OutputConstructor]
        private GetSchedulerJobCountsSchedulerJobAggregationCollectionItemDimensionResult(string lifecycleDetails)
        {
            LifecycleDetails = lifecycleDetails;
        }
    }
}
