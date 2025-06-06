// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DisasterRecovery.Inputs
{

    public sealed class DrProtectionGroupMemberNetworkLoadBalancerMappingGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the Network Load Balancer.  Example: `ocid1.networkloadbalancer.oc1..uniqueID`
        /// </summary>
        [Input("destinationNetworkLoadBalancerId")]
        public Input<string>? DestinationNetworkLoadBalancerId { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the source Network Load Balancer.  Example: `ocid1.networkloadbalancer.oc1..uniqueID`
        /// </summary>
        [Input("sourceNetworkLoadBalancerId")]
        public Input<string>? SourceNetworkLoadBalancerId { get; set; }

        public DrProtectionGroupMemberNetworkLoadBalancerMappingGetArgs()
        {
        }
        public static new DrProtectionGroupMemberNetworkLoadBalancerMappingGetArgs Empty => new DrProtectionGroupMemberNetworkLoadBalancerMappingGetArgs();
    }
}
