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
    public sealed class GetBackendSetsBackendsetSslConfigurationResult
    {
        /// <summary>
        /// Ids for Oracle Cloud Infrastructure certificates service certificates. Currently only a single Id may be passed.  Example: `[ocid1.certificate.oc1.us-ashburn-1.amaaaaaaav3bgsaa5o2q7rh5nfmkkukfkogasqhk6af2opufhjlqg7m6jqzq]`
        /// </summary>
        public readonly ImmutableArray<string> CertificateIds;
        /// <summary>
        /// A friendly name for the certificate bundle. It must be unique and it cannot be changed. Valid certificate bundle names include only alphanumeric characters, dashes, and underscores. Certificate bundle names cannot contain spaces. Avoid entering confidential information.  Example: `example_certificate_bundle`
        /// </summary>
        public readonly string CertificateName;
        /// <summary>
        /// The name of the cipher suite to use for HTTPS or SSL connections.
        /// </summary>
        public readonly string CipherSuiteName;
        /// <summary>
        /// A list of SSL protocols the load balancer must support for HTTPS or SSL connections.
        /// </summary>
        public readonly ImmutableArray<string> Protocols;
        /// <summary>
        /// When this attribute is set to ENABLED, the system gives preference to the server ciphers over the client ciphers.
        /// </summary>
        public readonly string ServerOrderPreference;
        /// <summary>
        /// Ids for Oracle Cloud Infrastructure certificates service CA or CA bundles for the load balancer to trust.  Example: `[ocid1.cabundle.oc1.us-ashburn-1.amaaaaaaav3bgsaagl4zzyqdop5i2vuwoqewdvauuw34llqa74otq2jdsfyq]`
        /// </summary>
        public readonly ImmutableArray<string> TrustedCertificateAuthorityIds;
        /// <summary>
        /// The maximum depth for peer certificate chain verification.  Example: `3`
        /// </summary>
        public readonly int VerifyDepth;
        /// <summary>
        /// Whether the load balancer listener should verify peer certificates.  Example: `true`
        /// </summary>
        public readonly bool VerifyPeerCertificate;

        [OutputConstructor]
        private GetBackendSetsBackendsetSslConfigurationResult(
            ImmutableArray<string> certificateIds,

            string certificateName,

            string cipherSuiteName,

            ImmutableArray<string> protocols,

            string serverOrderPreference,

            ImmutableArray<string> trustedCertificateAuthorityIds,

            int verifyDepth,

            bool verifyPeerCertificate)
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
