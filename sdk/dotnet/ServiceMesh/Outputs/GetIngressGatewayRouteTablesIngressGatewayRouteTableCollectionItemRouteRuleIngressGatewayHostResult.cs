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
    public sealed class GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRuleIngressGatewayHostResult
    {
        /// <summary>
        /// A filter to return only resources that match the entire name given.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The port of the ingress gateway host listener. Leave empty to match all ports for the host.
        /// </summary>
        public readonly int Port;

        [OutputConstructor]
        private GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRuleIngressGatewayHostResult(
            string name,

            int port)
        {
            Name = name;
            Port = port;
        }
    }
}
