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
    public sealed class GetCloudVmClustersCloudVmClusterIormConfigCachResult
    {
        public readonly ImmutableArray<Outputs.GetCloudVmClustersCloudVmClusterIormConfigCachDbPlanResult> DbPlans;
        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        public readonly string Objective;
        /// <summary>
        /// A filter to return only cloud VM clusters that match the given lifecycle state exactly.
        /// </summary>
        public readonly string State;

        [OutputConstructor]
        private GetCloudVmClustersCloudVmClusterIormConfigCachResult(
            ImmutableArray<Outputs.GetCloudVmClustersCloudVmClusterIormConfigCachDbPlanResult> dbPlans,

            string lifecycleDetails,

            string objective,

            string state)
        {
            DbPlans = dbPlans;
            LifecycleDetails = lifecycleDetails;
            Objective = objective;
            State = state;
        }
    }
}
