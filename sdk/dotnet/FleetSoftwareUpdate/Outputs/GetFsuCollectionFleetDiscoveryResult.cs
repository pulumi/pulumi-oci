// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetSoftwareUpdate.Outputs
{

    [OutputType]
    public sealed class GetFsuCollectionFleetDiscoveryResult
    {
        /// <summary>
        /// Filters to perform the target discovery.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFsuCollectionFleetDiscoveryFilterResult> Filters;
        /// <summary>
        /// OCIDs of Fleet Software Update Discovery.
        /// </summary>
        public readonly string FsuDiscoveryId;
        /// <summary>
        /// Oracle Cloud Infrastructure Search Service query string.
        /// </summary>
        public readonly string Query;
        /// <summary>
        /// Possible fleet discovery strategies.
        /// </summary>
        public readonly string Strategy;
        /// <summary>
        /// OCIDs of target resources to include. For EXACC service type Collections only VMClusters are allowed. For EXACS service type Collections only CloudVMClusters are allowed.
        /// </summary>
        public readonly ImmutableArray<string> Targets;

        [OutputConstructor]
        private GetFsuCollectionFleetDiscoveryResult(
            ImmutableArray<Outputs.GetFsuCollectionFleetDiscoveryFilterResult> filters,

            string fsuDiscoveryId,

            string query,

            string strategy,

            ImmutableArray<string> targets)
        {
            Filters = filters;
            FsuDiscoveryId = fsuDiscoveryId;
            Query = query;
            Strategy = strategy;
            Targets = targets;
        }
    }
}
