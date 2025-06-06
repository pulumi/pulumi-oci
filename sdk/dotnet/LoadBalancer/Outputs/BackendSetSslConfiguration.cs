// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer.Outputs
{

    [OutputType]
    public sealed class BackendSetSslConfiguration
    {
        /// <summary>
        /// (Updatable) Ids for Oracle Cloud Infrastructure certificates service certificates. Currently only a single Id may be passed.  Example: `[ocid1.certificate.oc1.us-ashburn-1.amaaaaaaav3bgsaa5o2q7rh5nfmkkukfkogasqhk6af2opufhjlqg7m6jqzq]`
        /// </summary>
        public readonly ImmutableArray<string> CertificateIds;
        /// <summary>
        /// (Updatable) A friendly name for the certificate bundle. It must be unique and it cannot be changed. Valid certificate bundle names include only alphanumeric characters, dashes, and underscores. Certificate bundle names cannot contain spaces. Avoid entering confidential information.  Example: `example_certificate_bundle`
        /// </summary>
        public readonly string? CertificateName;
        /// <summary>
        /// (Updatable) The name of the cipher suite to use for HTTPS or SSL connections.
        /// 
        /// If this field is not specified, the default is `oci-default-ssl-cipher-suite-v1`.
        /// 
        /// **Notes:**
        /// *  You must ensure compatibility between the specified SSL protocols and the ciphers configured in the cipher suite. Clients cannot perform an SSL handshake if there is an incompatible configuration.
        /// *  You must ensure compatibility between the ciphers configured in the cipher suite and the configured certificates. For example, RSA-based ciphers require RSA certificates and ECDSA-based ciphers require ECDSA certificates.
        /// *  If the cipher configuration is not modified after load balancer creation, the `GET` operation returns `oci-default-ssl-cipher-suite-v1` as the value of this field in the SSL configuration for existing listeners that predate this feature.
        /// *  If the cipher configuration was modified using Oracle operations after load balancer creation, the `GET` operation returns `oci-customized-ssl-cipher-suite` as the value of this field in the SSL configuration for existing listeners that predate this feature.
        /// *  The `GET` operation returns `oci-wider-compatible-ssl-cipher-suite-v1` as the value of this field in the SSL configuration for existing backend sets that predate this feature.
        /// *  If the `GET` operation on a listener returns `oci-customized-ssl-cipher-suite` as the value of this field, you must specify an appropriate predefined or custom cipher suite name when updating the resource.
        /// *  The `oci-customized-ssl-cipher-suite` Oracle reserved cipher suite name is not accepted as valid input for this field.
        /// 
        /// example: `example_cipher_suite`
        /// </summary>
        public readonly string? CipherSuiteName;
        /// <summary>
        /// (Updatable) A list of SSL protocols the load balancer must support for HTTPS or SSL connections.
        /// 
        /// The load balancer uses SSL protocols to establish a secure connection between a client and a server. A secure connection ensures that all data passed between the client and the server is private.
        /// 
        /// The Load Balancing service supports the following protocols:
        /// *  TLSv1
        /// *  TLSv1.1
        /// *  TLSv1.2
        /// *  TLSv1.3
        /// 
        /// If this field is not specified, TLSv1.2 is the default.
        /// 
        /// **Warning:** All SSL listeners created on a given port must use the same set of SSL protocols.
        /// 
        /// **Notes:**
        /// *  The handshake to establish an SSL connection fails if the client supports none of the specified protocols.
        /// *  You must ensure compatibility between the specified SSL protocols and the ciphers configured in the cipher suite.
        /// *  For all existing load balancer listeners and backend sets that predate this feature, the `GET` operation displays a list of SSL protocols currently used by those resources.
        /// 
        /// example: `["TLSv1.1", "TLSv1.2"]`
        /// </summary>
        public readonly ImmutableArray<string> Protocols;
        /// <summary>
        /// (Updatable) When this attribute is set to ENABLED, the system gives preference to the server ciphers over the client ciphers.
        /// 
        /// **Note:** This configuration is applicable only when the load balancer is acting as an SSL/HTTPS server. This field is ignored when the `SSLConfiguration` object is associated with a backend set.
        /// </summary>
        public readonly string? ServerOrderPreference;
        /// <summary>
        /// (Updatable) Ids for Oracle Cloud Infrastructure certificates service CA or CA bundles for the load balancer to trust.  Example: `[ocid1.cabundle.oc1.us-ashburn-1.amaaaaaaav3bgsaagl4zzyqdop5i2vuwoqewdvauuw34llqa74otq2jdsfyq]`
        /// </summary>
        public readonly ImmutableArray<string> TrustedCertificateAuthorityIds;
        /// <summary>
        /// (Updatable) The maximum depth for peer certificate chain verification.  Example: `3`
        /// </summary>
        public readonly int? VerifyDepth;
        /// <summary>
        /// (Updatable) Whether the load balancer listener should verify peer certificates.  Example: `true` 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public readonly bool? VerifyPeerCertificate;

        [OutputConstructor]
        private BackendSetSslConfiguration(
            ImmutableArray<string> certificateIds,

            string? certificateName,

            string? cipherSuiteName,

            ImmutableArray<string> protocols,

            string? serverOrderPreference,

            ImmutableArray<string> trustedCertificateAuthorityIds,

            int? verifyDepth,

            bool? verifyPeerCertificate)
        {
            CertificateIds = certificateIds;
            CertificateName = certificateName;
            CipherSuiteName = cipherSuiteName;
            Protocols = protocols;
            ServerOrderPreference = serverOrderPreference;
            TrustedCertificateAuthorityIds = trustedCertificateAuthorityIds;
            VerifyDepth = verifyDepth;
            VerifyPeerCertificate = verifyPeerCertificate;
        }
    }
}
