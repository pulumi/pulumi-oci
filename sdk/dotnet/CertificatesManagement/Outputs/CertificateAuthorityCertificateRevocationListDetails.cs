// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CertificatesManagement.Outputs
{

    [OutputType]
    public sealed class CertificateAuthorityCertificateRevocationListDetails
    {
        /// <summary>
        /// (Updatable) Optional CRL access points, expressed using a format where the version number of the issuing CA is inserted wherever you include a pair of curly braces. This versioning scheme helps avoid collisions when new CA versions are created. For example, myCrlFileIssuedFromCAVersion{}.crl becomes myCrlFileIssuedFromCAVersion2.crl for CA version 2.
        /// </summary>
        public readonly ImmutableArray<string> CustomFormattedUrls;
        /// <summary>
        /// (Updatable) The details of the Object Storage bucket configured to store the certificate revocation list (CRL).
        /// </summary>
        public readonly Outputs.CertificateAuthorityCertificateRevocationListDetailsObjectStorageConfig ObjectStorageConfig;

        [OutputConstructor]
        private CertificateAuthorityCertificateRevocationListDetails(
            ImmutableArray<string> customFormattedUrls,

            Outputs.CertificateAuthorityCertificateRevocationListDetailsObjectStorageConfig objectStorageConfig)
        {
            CustomFormattedUrls = customFormattedUrls;
            ObjectStorageConfig = objectStorageConfig;
        }
    }
}