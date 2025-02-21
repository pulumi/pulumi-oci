// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ServiceMesh.Inputs
{

    public sealed class IngressGatewayHostListenerTlsArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Resource representing the TLS configuration used for validating client certificates.
        /// </summary>
        [Input("clientValidation")]
        public Input<Inputs.IngressGatewayHostListenerTlsClientValidationArgs>? ClientValidation { get; set; }

        /// <summary>
        /// (Updatable) DISABLED: Connection can only be plaintext. PERMISSIVE: Connection can be either plaintext or TLS/mTLS. If the clientValidation.trustedCaBundle property is configured for the listener, mTLS is performed and the client's certificates are validated by the gateway. TLS: Connection can only be TLS.  MUTUAL_TLS: Connection can only be MTLS.
        /// </summary>
        [Input("mode", required: true)]
        public Input<string> Mode { get; set; } = null!;

        /// <summary>
        /// (Updatable) Resource representing the location of the TLS certificate.
        /// </summary>
        [Input("serverCertificate")]
        public Input<Inputs.IngressGatewayHostListenerTlsServerCertificateArgs>? ServerCertificate { get; set; }

        public IngressGatewayHostListenerTlsArgs()
        {
        }
        public static new IngressGatewayHostListenerTlsArgs Empty => new IngressGatewayHostListenerTlsArgs();
    }
}
