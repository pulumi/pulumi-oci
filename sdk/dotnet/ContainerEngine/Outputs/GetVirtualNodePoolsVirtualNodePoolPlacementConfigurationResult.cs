// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Outputs
{

    [OutputType]
    public sealed class GetVirtualNodePoolsVirtualNodePoolPlacementConfigurationResult
    {
        /// <summary>
        /// The availability domain in which to place virtual nodes. Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// The fault domain of this virtual node.
        /// </summary>
        public readonly ImmutableArray<string> FaultDomains;
        /// <summary>
        /// The regional subnet where pods' VNIC will be placed.
        /// </summary>
        public readonly string SubnetId;

        [OutputConstructor]
        private GetVirtualNodePoolsVirtualNodePoolPlacementConfigurationResult(
            string availabilityDomain,

            ImmutableArray<string> faultDomains,

            string subnetId)
        {
            AvailabilityDomain = availabilityDomain;
            FaultDomains = faultDomains;
            SubnetId = subnetId;
        }
    }
}
