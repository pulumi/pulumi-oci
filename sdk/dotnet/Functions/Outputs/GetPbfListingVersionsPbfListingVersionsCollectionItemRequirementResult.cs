// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Functions.Outputs
{

    [OutputType]
    public sealed class GetPbfListingVersionsPbfListingVersionsCollectionItemRequirementResult
    {
        /// <summary>
        /// Minimum memory required by this PBF. The user should use memory greater than or equal to  this value while configuring the Function.
        /// </summary>
        public readonly string MinMemoryRequiredInMbs;
        /// <summary>
        /// List of policies required for this PBF execution.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPbfListingVersionsPbfListingVersionsCollectionItemRequirementPolicyResult> Policies;

        [OutputConstructor]
        private GetPbfListingVersionsPbfListingVersionsCollectionItemRequirementResult(
            string minMemoryRequiredInMbs,

            ImmutableArray<Outputs.GetPbfListingVersionsPbfListingVersionsCollectionItemRequirementPolicyResult> policies)
        {
            MinMemoryRequiredInMbs = minMemoryRequiredInMbs;
            Policies = policies;
        }
    }
}