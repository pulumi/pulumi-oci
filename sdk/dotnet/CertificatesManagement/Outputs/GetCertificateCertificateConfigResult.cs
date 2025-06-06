// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CertificatesManagement.Outputs
{

    [OutputType]
    public sealed class GetCertificateCertificateConfigResult
    {
        /// <summary>
        /// The name of the profile used to create the certificate, which depends on the type of certificate you need.
        /// </summary>
        public readonly string CertificateProfileType;
        /// <summary>
        /// The origin of the certificate.
        /// </summary>
        public readonly string ConfigType;
        public readonly string CsrPem;
        /// <summary>
        /// The OCID of the certificate authority (CA) that issued the certificate.
        /// </summary>
        public readonly string IssuerCertificateAuthorityId;
        /// <summary>
        /// The algorithm used to create key pairs.
        /// </summary>
        public readonly string KeyAlgorithm;
        /// <summary>
        /// The algorithm used to sign the public key certificate.
        /// </summary>
        public readonly string SignatureAlgorithm;
        /// <summary>
        /// A list of subject alternative names.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetCertificateCertificateConfigSubjectAlternativeNameResult> SubjectAlternativeNames;
        /// <summary>
        /// The subject of the certificate, which is a distinguished name that identifies the entity that owns the public key in the certificate.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetCertificateCertificateConfigSubjectResult> Subjects;
        /// <summary>
        /// An object that describes a period of time during which an entity is valid. If this is not provided when you create a certificate, the validity of the issuing CA is used.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetCertificateCertificateConfigValidityResult> Validities;
        /// <summary>
        /// The name of the certificate version. When the value is not null, a name is unique across versions of a given certificate.
        /// </summary>
        public readonly string VersionName;

        [OutputConstructor]
        private GetCertificateCertificateConfigResult(
            string certificateProfileType,

            string configType,

            string csrPem,

            string issuerCertificateAuthorityId,

            string keyAlgorithm,

            string signatureAlgorithm,

            ImmutableArray<Outputs.GetCertificateCertificateConfigSubjectAlternativeNameResult> subjectAlternativeNames,

            ImmutableArray<Outputs.GetCertificateCertificateConfigSubjectResult> subjects,

            ImmutableArray<Outputs.GetCertificateCertificateConfigValidityResult> validities,

            string versionName)
        {
            CertificateProfileType = certificateProfileType;
            ConfigType = configType;
            CsrPem = csrPem;
            IssuerCertificateAuthorityId = issuerCertificateAuthorityId;
            KeyAlgorithm = keyAlgorithm;
            SignatureAlgorithm = signatureAlgorithm;
            SubjectAlternativeNames = subjectAlternativeNames;
            Subjects = subjects;
            Validities = validities;
            VersionName = versionName;
        }
    }
}
