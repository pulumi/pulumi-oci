// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class GetDomainsOauthClientCertificatesOauthClientCertificateResult
    {
        /// <summary>
        /// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
        /// </summary>
        public readonly string Authorization;
        /// <summary>
        /// Certificate end date
        /// </summary>
        public readonly string CertEndDate;
        /// <summary>
        /// Certificate start date
        /// </summary>
        public readonly string CertStartDate;
        /// <summary>
        /// Certificate alias
        /// </summary>
        public readonly string CertificateAlias;
        /// <summary>
        /// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string CompartmentOcid;
        /// <summary>
        /// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
        /// </summary>
        public readonly bool DeleteInProgress;
        /// <summary>
        /// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string DomainOcid;
        /// <summary>
        /// An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service Provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value. The value of the externalId attribute is always issued by the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer's tenant.
        /// </summary>
        public readonly string ExternalId;
        /// <summary>
        /// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The User or App who created the Resource
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsOauthClientCertificatesOauthClientCertificateIdcsCreatedByResult> IdcsCreatedBies;
        /// <summary>
        /// The basic endpoint for the identity domain
        /// </summary>
        public readonly string IdcsEndpoint;
        /// <summary>
        /// The User or App who modified the Resource
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsOauthClientCertificatesOauthClientCertificateIdcsLastModifiedByResult> IdcsLastModifiedBies;
        /// <summary>
        /// The release number when the resource was upgraded.
        /// </summary>
        public readonly string IdcsLastUpgradedInRelease;
        /// <summary>
        /// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
        /// </summary>
        public readonly ImmutableArray<string> IdcsPreventedOperations;
        /// <summary>
        /// Key store ID
        /// </summary>
        public readonly string KeyStoreId;
        /// <summary>
        /// Key store name
        /// </summary>
        public readonly string KeyStoreName;
        /// <summary>
        /// Key store password
        /// </summary>
        public readonly string KeyStorePassword;
        /// <summary>
        /// Map
        /// </summary>
        public readonly string Map;
        /// <summary>
        /// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsOauthClientCertificatesOauthClientCertificateMetaResult> Metas;
        /// <summary>
        /// Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
        /// </summary>
        public readonly string Ocid;
        /// <summary>
        /// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
        /// </summary>
        public readonly string ResourceTypeSchemaVersion;
        /// <summary>
        /// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
        /// </summary>
        public readonly ImmutableArray<string> Schemas;
        /// <summary>
        /// SHA-1 Thumbprint
        /// </summary>
        public readonly string Sha1thumbprint;
        /// <summary>
        /// SHA-256 Thumbprint
        /// </summary>
        public readonly string Sha256thumbprint;
        /// <summary>
        /// A list of tags on this resource.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsOauthClientCertificatesOauthClientCertificateTagResult> Tags;
        /// <summary>
        /// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string TenancyOcid;
        /// <summary>
        /// Base 64Key data attribute
        /// </summary>
        public readonly string X509base64certificate;

        [OutputConstructor]
        private GetDomainsOauthClientCertificatesOauthClientCertificateResult(
            string authorization,

            string certEndDate,

            string certStartDate,

            string certificateAlias,

            string compartmentOcid,

            bool deleteInProgress,

            string domainOcid,

            string externalId,

            string id,

            ImmutableArray<Outputs.GetDomainsOauthClientCertificatesOauthClientCertificateIdcsCreatedByResult> idcsCreatedBies,

            string idcsEndpoint,

            ImmutableArray<Outputs.GetDomainsOauthClientCertificatesOauthClientCertificateIdcsLastModifiedByResult> idcsLastModifiedBies,

            string idcsLastUpgradedInRelease,

            ImmutableArray<string> idcsPreventedOperations,

            string keyStoreId,

            string keyStoreName,

            string keyStorePassword,

            string map,

            ImmutableArray<Outputs.GetDomainsOauthClientCertificatesOauthClientCertificateMetaResult> metas,

            string ocid,

            string resourceTypeSchemaVersion,

            ImmutableArray<string> schemas,

            string sha1thumbprint,

            string sha256thumbprint,

            ImmutableArray<Outputs.GetDomainsOauthClientCertificatesOauthClientCertificateTagResult> tags,

            string tenancyOcid,

            string x509base64certificate)
        {
            Authorization = authorization;
            CertEndDate = certEndDate;
            CertStartDate = certStartDate;
            CertificateAlias = certificateAlias;
            CompartmentOcid = compartmentOcid;
            DeleteInProgress = deleteInProgress;
            DomainOcid = domainOcid;
            ExternalId = externalId;
            Id = id;
            IdcsCreatedBies = idcsCreatedBies;
            IdcsEndpoint = idcsEndpoint;
            IdcsLastModifiedBies = idcsLastModifiedBies;
            IdcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            IdcsPreventedOperations = idcsPreventedOperations;
            KeyStoreId = keyStoreId;
            KeyStoreName = keyStoreName;
            KeyStorePassword = keyStorePassword;
            Map = map;
            Metas = metas;
            Ocid = ocid;
            ResourceTypeSchemaVersion = resourceTypeSchemaVersion;
            Schemas = schemas;
            Sha1thumbprint = sha1thumbprint;
            Sha256thumbprint = sha256thumbprint;
            Tags = tags;
            TenancyOcid = tenancyOcid;
            X509base64certificate = x509base64certificate;
        }
    }
}
