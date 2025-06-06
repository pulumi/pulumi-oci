// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    public static class GetDomainsGrant
    {
        /// <summary>
        /// This data source provides details about a specific Grant resource in Oracle Cloud Infrastructure Identity Domains service.
        /// 
        /// Get a Grant
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testGrant = Oci.Identity.GetDomainsGrant.Invoke(new()
        ///     {
        ///         GrantId = testGrantOciIdentityDomainsGrant.Id,
        ///         IdcsEndpoint = testDomain.Url,
        ///         AttributeSets = new[]
        ///         {
        ///             "all",
        ///         },
        ///         Attributes = "",
        ///         Authorization = grantAuthorization,
        ///         ResourceTypeSchemaVersion = grantResourceTypeSchemaVersion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDomainsGrantResult> InvokeAsync(GetDomainsGrantArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDomainsGrantResult>("oci:Identity/getDomainsGrant:getDomainsGrant", args ?? new GetDomainsGrantArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Grant resource in Oracle Cloud Infrastructure Identity Domains service.
        /// 
        /// Get a Grant
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testGrant = Oci.Identity.GetDomainsGrant.Invoke(new()
        ///     {
        ///         GrantId = testGrantOciIdentityDomainsGrant.Id,
        ///         IdcsEndpoint = testDomain.Url,
        ///         AttributeSets = new[]
        ///         {
        ///             "all",
        ///         },
        ///         Attributes = "",
        ///         Authorization = grantAuthorization,
        ///         ResourceTypeSchemaVersion = grantResourceTypeSchemaVersion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDomainsGrantResult> Invoke(GetDomainsGrantInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDomainsGrantResult>("oci:Identity/getDomainsGrant:getDomainsGrant", args ?? new GetDomainsGrantInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Grant resource in Oracle Cloud Infrastructure Identity Domains service.
        /// 
        /// Get a Grant
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testGrant = Oci.Identity.GetDomainsGrant.Invoke(new()
        ///     {
        ///         GrantId = testGrantOciIdentityDomainsGrant.Id,
        ///         IdcsEndpoint = testDomain.Url,
        ///         AttributeSets = new[]
        ///         {
        ///             "all",
        ///         },
        ///         Attributes = "",
        ///         Authorization = grantAuthorization,
        ///         ResourceTypeSchemaVersion = grantResourceTypeSchemaVersion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDomainsGrantResult> Invoke(GetDomainsGrantInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDomainsGrantResult>("oci:Identity/getDomainsGrant:getDomainsGrant", args ?? new GetDomainsGrantInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDomainsGrantArgs : global::Pulumi.InvokeArgs
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
        /// ID of the resource
        /// </summary>
        [Input("grantId", required: true)]
        public string GrantId { get; set; } = null!;

        /// <summary>
        /// The basic endpoint for the identity domain
        /// </summary>
        [Input("idcsEndpoint", required: true)]
        public string IdcsEndpoint { get; set; } = null!;

        /// <summary>
        /// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
        /// </summary>
        [Input("resourceTypeSchemaVersion")]
        public string? ResourceTypeSchemaVersion { get; set; }

        public GetDomainsGrantArgs()
        {
        }
        public static new GetDomainsGrantArgs Empty => new GetDomainsGrantArgs();
    }

    public sealed class GetDomainsGrantInvokeArgs : global::Pulumi.InvokeArgs
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
        /// ID of the resource
        /// </summary>
        [Input("grantId", required: true)]
        public Input<string> GrantId { get; set; } = null!;

        /// <summary>
        /// The basic endpoint for the identity domain
        /// </summary>
        [Input("idcsEndpoint", required: true)]
        public Input<string> IdcsEndpoint { get; set; } = null!;

        /// <summary>
        /// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
        /// </summary>
        [Input("resourceTypeSchemaVersion")]
        public Input<string>? ResourceTypeSchemaVersion { get; set; }

        public GetDomainsGrantInvokeArgs()
        {
        }
        public static new GetDomainsGrantInvokeArgs Empty => new GetDomainsGrantInvokeArgs();
    }


    [OutputType]
    public sealed class GetDomainsGrantResult
    {
        /// <summary>
        /// Application-Entitlement-Collection that is being granted. Each Grant must grant either an App or an App-Entitlement-Collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsGrantAppEntitlementCollectionResult> AppEntitlementCollections;
        /// <summary>
        /// Application that is being granted. Each Grant must grant either an App or an App-Entitlement-Collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsGrantAppResult> Apps;
        public readonly ImmutableArray<string> AttributeSets;
        public readonly string? Attributes;
        public readonly string? Authorization;
        /// <summary>
        /// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string CompartmentOcid;
        /// <summary>
        /// Unique key of grant, composed by combining a subset of app, entitlement, grantee, grantor and grantMechanism.  Used to prevent duplicate Grants.
        /// </summary>
        public readonly string CompositeKey;
        /// <summary>
        /// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
        /// </summary>
        public readonly bool DeleteInProgress;
        /// <summary>
        /// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string DomainOcid;
        /// <summary>
        /// The entitlement or privilege that is being granted
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsGrantEntitlementResult> Entitlements;
        public readonly string GrantId;
        /// <summary>
        /// Each value of grantMechanism indicates how (or by what component) some App (or App-Entitlement) was granted. A customer or the UI should use only grantMechanism values that start with 'ADMINISTRATOR':
        /// * 'ADMINISTRATOR_TO_USER' is for a direct grant to a specific User.
        /// * 'ADMINISTRATOR_TO_GROUP' is for a grant to a specific Group, which results in indirect grants to Users who are members of that Group.
        /// * 'ADMINISTRATOR_TO_APP' is for a grant to a specific App.  The grantee (client) App gains access to the granted (server) App.
        /// </summary>
        public readonly string GrantMechanism;
        /// <summary>
        /// Store granted attribute-values as a string in Javascript Object Notation (JSON) format.
        /// </summary>
        public readonly string GrantedAttributeValuesJson;
        /// <summary>
        /// Grantee beneficiary. The grantee may be a User, Group, App or DynamicResourceGroup.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsGrantGranteeResult> Grantees;
        /// <summary>
        /// User conferring the grant to the beneficiary
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsGrantGrantorResult> Grantors;
        /// <summary>
        /// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The User or App who created the Resource
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsGrantIdcsCreatedByResult> IdcsCreatedBies;
        public readonly string IdcsEndpoint;
        /// <summary>
        /// The User or App who modified the Resource
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsGrantIdcsLastModifiedByResult> IdcsLastModifiedBies;
        /// <summary>
        /// The release number when the resource was upgraded.
        /// </summary>
        public readonly string IdcsLastUpgradedInRelease;
        /// <summary>
        /// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
        /// </summary>
        public readonly ImmutableArray<string> IdcsPreventedOperations;
        /// <summary>
        /// If true, this Grant has been fulfilled successfully.
        /// </summary>
        public readonly bool IsFulfilled;
        /// <summary>
        /// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsGrantMetaResult> Metas;
        /// <summary>
        /// Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
        /// </summary>
        public readonly string Ocid;
        public readonly string? ResourceTypeSchemaVersion;
        /// <summary>
        /// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
        /// </summary>
        public readonly ImmutableArray<string> Schemas;
        /// <summary>
        /// A list of tags on this resource.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsGrantTagResult> Tags;
        /// <summary>
        /// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string TenancyOcid;

        [OutputConstructor]
        private GetDomainsGrantResult(
            ImmutableArray<Outputs.GetDomainsGrantAppEntitlementCollectionResult> appEntitlementCollections,

            ImmutableArray<Outputs.GetDomainsGrantAppResult> apps,

            ImmutableArray<string> attributeSets,

            string? attributes,

            string? authorization,

            string compartmentOcid,

            string compositeKey,

            bool deleteInProgress,

            string domainOcid,

            ImmutableArray<Outputs.GetDomainsGrantEntitlementResult> entitlements,

            string grantId,

            string grantMechanism,

            string grantedAttributeValuesJson,

            ImmutableArray<Outputs.GetDomainsGrantGranteeResult> grantees,

            ImmutableArray<Outputs.GetDomainsGrantGrantorResult> grantors,

            string id,

            ImmutableArray<Outputs.GetDomainsGrantIdcsCreatedByResult> idcsCreatedBies,

            string idcsEndpoint,

            ImmutableArray<Outputs.GetDomainsGrantIdcsLastModifiedByResult> idcsLastModifiedBies,

            string idcsLastUpgradedInRelease,

            ImmutableArray<string> idcsPreventedOperations,

            bool isFulfilled,

            ImmutableArray<Outputs.GetDomainsGrantMetaResult> metas,

            string ocid,

            string? resourceTypeSchemaVersion,

            ImmutableArray<string> schemas,

            ImmutableArray<Outputs.GetDomainsGrantTagResult> tags,

            string tenancyOcid)
        {
            AppEntitlementCollections = appEntitlementCollections;
            Apps = apps;
            AttributeSets = attributeSets;
            Attributes = attributes;
            Authorization = authorization;
            CompartmentOcid = compartmentOcid;
            CompositeKey = compositeKey;
            DeleteInProgress = deleteInProgress;
            DomainOcid = domainOcid;
            Entitlements = entitlements;
            GrantId = grantId;
            GrantMechanism = grantMechanism;
            GrantedAttributeValuesJson = grantedAttributeValuesJson;
            Grantees = grantees;
            Grantors = grantors;
            Id = id;
            IdcsCreatedBies = idcsCreatedBies;
            IdcsEndpoint = idcsEndpoint;
            IdcsLastModifiedBies = idcsLastModifiedBies;
            IdcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            IdcsPreventedOperations = idcsPreventedOperations;
            IsFulfilled = isFulfilled;
            Metas = metas;
            Ocid = ocid;
            ResourceTypeSchemaVersion = resourceTypeSchemaVersion;
            Schemas = schemas;
            Tags = tags;
            TenancyOcid = tenancyOcid;
        }
    }
}
