// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ServiceMesh.Outputs
{

    [OutputType]
    public sealed class GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRuleDestinationResult
    {
        /// <summary>
        /// The port of the ingress gateway host listener. Leave empty to match all ports for the host.
        /// </summary>
        public readonly int Port;
        /// <summary>
        /// The OCID of the virtual service where the request will be routed.
        /// </summary>
        public readonly string VirtualServiceId;
        /// <summary>
        /// Weight of traffic target.
        /// </summary>
        public readonly int Weight;

        [OutputConstructor]
        private GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRuleDestinationResult(
            int port,

            string virtualServiceId,

            int weight)
        {
            Port = port;
            VirtualServiceId = virtualServiceId;
            Weight = weight;
        }
    }
}