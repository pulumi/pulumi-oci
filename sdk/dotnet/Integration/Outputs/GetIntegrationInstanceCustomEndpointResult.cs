// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Integration.Outputs
{

    [OutputType]
    public sealed class GetIntegrationInstanceCustomEndpointResult
    {
        /// <summary>
        /// Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname.
        /// </summary>
        public readonly string CertificateSecretId;
        /// <summary>
        /// The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
        /// </summary>
        public readonly int CertificateSecretVersion;
        /// <summary>
        /// A custom hostname to be used for the integration instance URL, in FQDN format.
        /// </summary>
        public readonly string Hostname;

        [OutputConstructor]
        private GetIntegrationInstanceCustomEndpointResult(
            string certificateSecretId,

            int certificateSecretVersion,

            string hostname)
        {
            CertificateSecretId = certificateSecretId;
            CertificateSecretVersion = certificateSecretVersion;
            Hostname = hostname;
        }
    }
}
