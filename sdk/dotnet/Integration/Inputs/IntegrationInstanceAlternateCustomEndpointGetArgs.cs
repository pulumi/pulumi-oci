// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Integration.Inputs
{

    public sealed class IntegrationInstanceAlternateCustomEndpointGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// When creating the DNS CNAME record for the custom hostname, this value must be specified in the rdata.
        /// </summary>
        [Input("alias")]
        public Input<string>? Alias { get; set; }

        /// <summary>
        /// (Updatable) Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname. All certificates should be stored in a single base64 encoded secret Note the update will fail if this is not a valid certificate.
        /// </summary>
        [Input("certificateSecretId")]
        public Input<string>? CertificateSecretId { get; set; }

        /// <summary>
        /// The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
        /// </summary>
        [Input("certificateSecretVersion")]
        public Input<int>? CertificateSecretVersion { get; set; }

        /// <summary>
        /// (Updatable) A custom hostname to be used for the integration instance URL, in FQDN format.
        /// </summary>
        [Input("hostname", required: true)]
        public Input<string> Hostname { get; set; } = null!;

        public IntegrationInstanceAlternateCustomEndpointGetArgs()
        {
        }
        public static new IntegrationInstanceAlternateCustomEndpointGetArgs Empty => new IntegrationInstanceAlternateCustomEndpointGetArgs();
    }
}