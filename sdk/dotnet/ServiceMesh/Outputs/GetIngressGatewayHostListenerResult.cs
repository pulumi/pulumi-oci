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
    public sealed class GetIngressGatewayHostListenerResult
    {
        /// <summary>
        /// Port on which ingress gateway is listening.
        /// </summary>
        public readonly int Port;
        /// <summary>
        /// Type of protocol used.
        /// </summary>
        public readonly string Protocol;
        /// <summary>
        /// TLS enforcement config for the ingress listener.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetIngressGatewayHostListenerTlResult> Tls;

        [OutputConstructor]
        private GetIngressGatewayHostListenerResult(
            int port,

            string protocol,

            ImmutableArray<Outputs.GetIngressGatewayHostListenerTlResult> tls)
        {
            Port = port;
            Protocol = protocol;
            Tls = tls;
        }
    }
}