// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CertificatesManagement.Inputs
{

    public sealed class CertificateCertificateRevocationListDetailGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("customFormattedUrls")]
        private InputList<string>? _customFormattedUrls;

        /// <summary>
        /// Optional CRL access points, expressed using a format where the version number of the issuing CA is inserted wherever you include a pair of curly braces. This versioning scheme helps avoid collisions when new CA versions are created. For example, myCrlFileIssuedFromCAVersion{}.crl becomes myCrlFileIssuedFromCAVersion2.crl for CA version 2.
        /// </summary>
        public InputList<string> CustomFormattedUrls
        {
            get => _customFormattedUrls ?? (_customFormattedUrls = new InputList<string>());
            set => _customFormattedUrls = value;
        }

        [Input("objectStorageConfigs")]
        private InputList<Inputs.CertificateCertificateRevocationListDetailObjectStorageConfigGetArgs>? _objectStorageConfigs;

        /// <summary>
        /// The details of the Object Storage bucket configured to store the certificate revocation list (CRL).
        /// </summary>
        public InputList<Inputs.CertificateCertificateRevocationListDetailObjectStorageConfigGetArgs> ObjectStorageConfigs
        {
            get => _objectStorageConfigs ?? (_objectStorageConfigs = new InputList<Inputs.CertificateCertificateRevocationListDetailObjectStorageConfigGetArgs>());
            set => _objectStorageConfigs = value;
        }

        public CertificateCertificateRevocationListDetailGetArgs()
        {
        }
        public static new CertificateCertificateRevocationListDetailGetArgs Empty => new CertificateCertificateRevocationListDetailGetArgs();
    }
}