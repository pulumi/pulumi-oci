// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ComputeCloud.Outputs
{

    [OutputType]
    public sealed class GetAtCustomerCccInfrastructuresCccInfrastructureCollectionItemInfrastructureNetworkConfigurationInfrastructureRoutingStaticResult
    {
        /// <summary>
        /// The uplink Hot Standby Router Protocol (HSRP) group value for the switch in the Compute Cloud@Customer infrastructure.
        /// </summary>
        public readonly int UplinkHsrpGroup;
        /// <summary>
        /// The virtual local area network (VLAN) identifier used to connect to the uplink (only access mode is supported).
        /// </summary>
        public readonly int UplinkVlan;

        [OutputConstructor]
        private GetAtCustomerCccInfrastructuresCccInfrastructureCollectionItemInfrastructureNetworkConfigurationInfrastructureRoutingStaticResult(
            int uplinkHsrpGroup,

            int uplinkVlan)
        {
            UplinkHsrpGroup = uplinkHsrpGroup;
            UplinkVlan = uplinkVlan;
        }
    }
}
