// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    public static class GetDomainsOauth2clientCredential
    {
        /// <summary>
        /// This data source provides details about a specific O Auth2 Client Credential resource in Oracle Cloud Infrastructure Identity Domains service.
        /// 
        /// Get user's oauth2 client credential
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testOauth2clientCredential = Oci.Identity.GetDomainsOauth2clientCredential.Invoke(new()
        ///     {
        ///         IdcsEndpoint = data.Oci_identity_domain.Test_domain.Url,
        ///         OAuth2clientCredentialId = oci_identity_domains_o_auth2client_credential.Test_o_auth2client_credential.Id,
        ///         AttributeSets = new[] {},
        ///         Attributes = "",
        ///         Authorization = @var.Oauth2client_credential_authorization,
        ///         ResourceTypeSchemaVersion = @var.Oauth2client_credential_resource_type_schema_version,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDomainsOauth2clientCredentialResult> InvokeAsync(GetDomainsOauth2clientCredentialArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDomainsOauth2clientCredentialResult>("oci:Identity/getDomainsOauth2clientCredential:getDomainsOauth2clientCredential", args ?? new GetDomainsOauth2clientCredentialArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific O Auth2 Client Credential resource in Oracle Cloud Infrastructure Identity Domains service.
        /// 
        /// Get user's oauth2 client credential
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testOauth2clientCredential = Oci.Identity.GetDomainsOauth2clientCredential.Invoke(new()
        ///     {
        ///         IdcsEndpoint = data.Oci_identity_domain.Test_domain.Url,
        ///         OAuth2clientCredentialId = oci_identity_domains_o_auth2client_credential.Test_o_auth2client_credential.Id,
        ///         AttributeSets = new[] {},
        ///         Attributes = "",
        ///         Authorization = @var.Oauth2client_credential_authorization,
        ///         ResourceTypeSchemaVersion = @var.Oauth2client_credential_resource_type_schema_version,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetDomainsOauth2clientCredentialResult> Invoke(GetDomainsOauth2clientCredentialInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDomainsOauth2clientCredentialResult>("oci:Identity/getDomainsOauth2clientCredential:getDomainsOauth2clientCredential", args ?? new GetDomainsOauth2clientCredentialInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDomainsOauth2clientCredentialArgs : global::Pulumi.InvokeArgs
    {
        [Input("attributeSets")]
        private List<string>? _attributeSets;

        /// <summary>
        /// A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
        /// </summary>
        public List<string> AttributeSets
        {
            get => _attributeSets ?? (_attributeSets = new List<string>());
            set => _attributeSets = value;
        }

        /// <summary>
        /// A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
        /// </summary>
        [Input("attributes")]
        public string? Attributes { get; set; }

        /// <summary>
        /// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
        /// </summary>
        [Input("authorization")]
        public string? Authorization { get; set; }

        /// <summary>
        /// The basic endpoint for the identity domain
        /// </summary>
        [Input("idcsEndpoint", required: true)]
        public string IdcsEndpoint { get; set; } = null!;

        /// <summary>
        /// ID of the resource
        /// </summary>
        [Input("oAuth2clientCredentialId", required: true)]
        public string OAuth2clientCredentialId { get; set; } = null!;

        /// <summary>
        /// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
        /// </summary>
        [Input("resourceTypeSchemaVersion")]
        public string? ResourceTypeSchemaVersion { get; set; }

        public GetDomainsOauth2clientCredentialArgs()
        {
        }
        public static new GetDomainsOauth2clientCredentialArgs Empty => new GetDomainsOauth2clientCredentialArgs();
    }

    public sealed class GetDomainsOauth2clientCredentialInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("attributeSets")]
        private InputList<string>? _attributeSets;

        /// <summary>
        /// A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
        /// </summary>
        public InputList<string> AttributeSets
        {
            get => _attributeSets ?? (_attributeSets = new InputList<string>());
            set => _attributeSets = value;
        }

        /// <summary>
        /// A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
        /// </summary>
        [Input("attributes")]
        public Input<string>? Attributes { get; set; }

        /// <summary>
        /// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
        /// </summary>
        [Input("authorization")]
        public Input<string>? Authorization { get; set; }

        /// <summary>
        /// The basic endpoint for the identity domain
        /// </summary>
        [Input("idcsEndpoint", required: true)]
        public Input<string> IdcsEndpoint { get; set; } = null!;

        /// <summary>
        /// ID of the resource
        /// </summary>
        [Input("oAuth2clientCredentialId", required: true)]
        public Input<string> OAuth2clientCredentialId { get; set; } = null!;

        /// <summary>
        /// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
        /// </summary>
        [Input("resourceTypeSchemaVersion")]
        public Input<string>? ResourceTypeSchemaVersion { get; set; }

        public GetDomainsOauth2clientCredentialInvokeArgs()
        {
        }
        public static new GetDomainsOauth2clientCredentialInvokeArgs Empty => new GetDomainsOauth2clientCredentialInvokeArgs();
    }


    [OutputType]
    public sealed class GetDomainsOauth2clientCredentialResult
    {
        public readonly ImmutableArray<string> AttributeSets;
        public readonly string? Attributes;
        public readonly string? Authorization;
        /// <summary>
        /// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string CompartmentOcid;
        /// <summary>
        /// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
        /// </summary>
        public readonly bool DeleteInProgress;
        /// <summary>
        /// Description
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string DomainOcid;
        /// <summary>
        /// User credential expires on
        /// </summary>
        public readonly string ExpiresOn;
        /// <summary>
        /// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The User or App who created the Resource
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsOauth2clientCredentialIdcsCreatedByResult> IdcsCreatedBies;
        public readonly string IdcsEndpoint;
        /// <summary>
        /// The User or App who modified the Resource
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsOauth2clientCredentialIdcsLastModifiedByResult> IdcsLastModifiedBies;
        /// <summary>
        /// The release number when the resource was upgraded.
        /// </summary>
        public readonly string IdcsLastUpgradedInRelease;
        /// <summary>
        /// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
        /// </summary>
        public readonly ImmutableArray<string> IdcsPreventedOperations;
        /// <summary>
        /// Specifies if secret need to be reset
        /// </summary>
        public readonly bool IsResetSecret;
        /// <summary>
        /// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsOauth2clientCredentialMetaResult> Metas;
        /// <summary>
        /// User name
        /// </summary>
        public readonly string Name;
        public readonly string OAuth2clientCredentialId;
        /// <summary>
        /// User's ocid
        /// </summary>
        public readonly string Ocid;
        public readonly string? ResourceTypeSchemaVersion;
        /// <summary>
        /// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
        /// </summary>
        public readonly ImmutableArray<string> Schemas;
        /// <summary>
        /// Scopes
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsOauth2clientCredentialScopeResult> Scopes;
        /// <summary>
        /// User credential status
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// A list of tags on this resource.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsOauth2clientCredentialTagResult> Tags;
        /// <summary>
        /// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string TenancyOcid;
        /// <summary>
        /// Controls whether a user can update themselves or not via User related APIs
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsOauth2clientCredentialUrnietfparamsscimschemasoracleidcsextensionselfChangeUserResult> UrnietfparamsscimschemasoracleidcsextensionselfChangeUsers;
        /// <summary>
        /// User linked to oauth2 client credential
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsOauth2clientCredentialUserResult> Users;

        [OutputConstructor]
        private GetDomainsOauth2clientCredentialResult(
            ImmutableArray<string> attributeSets,

            string? attributes,

            string? authorization,

            string compartmentOcid,

            bool deleteInProgress,

            string description,

            string domainOcid,

            string expiresOn,

            string id,

            ImmutableArray<Outputs.GetDomainsOauth2clientCredentialIdcsCreatedByResult> idcsCreatedBies,

            string idcsEndpoint,

            ImmutableArray<Outputs.GetDomainsOauth2clientCredentialIdcsLastModifiedByResult> idcsLastModifiedBies,

            string idcsLastUpgradedInRelease,

            ImmutableArray<string> idcsPreventedOperations,

            bool isResetSecret,

            ImmutableArray<Outputs.GetDomainsOauth2clientCredentialMetaResult> metas,

            string name,

            string oAuth2clientCredentialId,

            string ocid,

            string? resourceTypeSchemaVersion,

            ImmutableArray<string> schemas,

            ImmutableArray<Outputs.GetDomainsOauth2clientCredentialScopeResult> scopes,

            string status,

            ImmutableArray<Outputs.GetDomainsOauth2clientCredentialTagResult> tags,

            string tenancyOcid,

            ImmutableArray<Outputs.GetDomainsOauth2clientCredentialUrnietfparamsscimschemasoracleidcsextensionselfChangeUserResult> urnietfparamsscimschemasoracleidcsextensionselfChangeUsers,

            ImmutableArray<Outputs.GetDomainsOauth2clientCredentialUserResult> users)
        {
            AttributeSets = attributeSets;
            Attributes = attributes;
            Authorization = authorization;
            CompartmentOcid = compartmentOcid;
            DeleteInProgress = deleteInProgress;
            Description = description;
            DomainOcid = domainOcid;
            ExpiresOn = expiresOn;
            Id = id;
            IdcsCreatedBies = idcsCreatedBies;
            IdcsEndpoint = idcsEndpoint;
            IdcsLastModifiedBies = idcsLastModifiedBies;
            IdcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            IdcsPreventedOperations = idcsPreventedOperations;
            IsResetSecret = isResetSecret;
            Metas = metas;
            Name = name;
            OAuth2clientCredentialId = oAuth2clientCredentialId;
            Ocid = ocid;
            ResourceTypeSchemaVersion = resourceTypeSchemaVersion;
            Schemas = schemas;
            Scopes = scopes;
            Status = status;
            Tags = tags;
            TenancyOcid = tenancyOcid;
            UrnietfparamsscimschemasoracleidcsextensionselfChangeUsers = urnietfparamsscimschemasoracleidcsextensionselfChangeUsers;
            Users = users;
        }
    }
}