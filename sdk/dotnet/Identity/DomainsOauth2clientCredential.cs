// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    /// <summary>
    /// This resource provides the O Auth2 Client Credential resource in Oracle Cloud Infrastructure Identity Domains service.
    /// 
    /// Add a user's oauth2 client credential
    /// 
    /// ## Import
    /// 
    /// OAuth2ClientCredentials can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:Identity/domainsOauth2clientCredential:DomainsOauth2clientCredential test_oauth2client_credential "idcsEndpoint/{idcsEndpoint}/oAuth2ClientCredentials/{oAuth2ClientCredentialId}"
    /// ```
    /// </summary>
    [OciResourceType("oci:Identity/domainsOauth2clientCredential:DomainsOauth2clientCredential")]
    public partial class DomainsOauth2clientCredential : global::Pulumi.CustomResource
    {
        /// <summary>
        /// A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
        /// </summary>
        [Output("attributeSets")]
        public Output<ImmutableArray<string>> AttributeSets { get; private set; } = null!;

        /// <summary>
        /// A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
        /// </summary>
        [Output("attributes")]
        public Output<string?> Attributes { get; private set; } = null!;

        /// <summary>
        /// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
        /// </summary>
        [Output("authorization")]
        public Output<string?> Authorization { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
        /// </summary>
        [Output("compartmentOcid")]
        public Output<string> CompartmentOcid { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
        /// </summary>
        [Output("deleteInProgress")]
        public Output<bool> DeleteInProgress { get; private set; } = null!;

        /// <summary>
        /// Description
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
        /// </summary>
        [Output("domainOcid")]
        public Output<string> DomainOcid { get; private set; } = null!;

        /// <summary>
        /// User credential expires on
        /// </summary>
        [Output("expiresOn")]
        public Output<string> ExpiresOn { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The User or App who created the Resource
        /// </summary>
        [Output("idcsCreatedBies")]
        public Output<ImmutableArray<Outputs.DomainsOauth2clientCredentialIdcsCreatedBy>> IdcsCreatedBies { get; private set; } = null!;

        /// <summary>
        /// The basic endpoint for the identity domain
        /// </summary>
        [Output("idcsEndpoint")]
        public Output<string> IdcsEndpoint { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The User or App who modified the Resource
        /// </summary>
        [Output("idcsLastModifiedBies")]
        public Output<ImmutableArray<Outputs.DomainsOauth2clientCredentialIdcsLastModifiedBy>> IdcsLastModifiedBies { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The release number when the resource was upgraded.
        /// </summary>
        [Output("idcsLastUpgradedInRelease")]
        public Output<string> IdcsLastUpgradedInRelease { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
        /// </summary>
        [Output("idcsPreventedOperations")]
        public Output<ImmutableArray<string>> IdcsPreventedOperations { get; private set; } = null!;

        /// <summary>
        /// Specifies if secret need to be reset
        /// </summary>
        [Output("isResetSecret")]
        public Output<bool> IsResetSecret { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
        /// </summary>
        [Output("metas")]
        public Output<ImmutableArray<Outputs.DomainsOauth2clientCredentialMeta>> Metas { get; private set; } = null!;

        /// <summary>
        /// (Updatable) User name
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// User's ocid
        /// </summary>
        [Output("ocid")]
        public Output<string> Ocid { get; private set; } = null!;

        /// <summary>
        /// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
        /// </summary>
        [Output("resourceTypeSchemaVersion")]
        public Output<string?> ResourceTypeSchemaVersion { get; private set; } = null!;

        /// <summary>
        /// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
        /// </summary>
        [Output("schemas")]
        public Output<ImmutableArray<string>> Schemas { get; private set; } = null!;

        /// <summary>
        /// Scopes
        /// </summary>
        [Output("scopes")]
        public Output<ImmutableArray<Outputs.DomainsOauth2clientCredentialScope>> Scopes { get; private set; } = null!;

        /// <summary>
        /// User credential status
        /// </summary>
        [Output("status")]
        public Output<string> Status { get; private set; } = null!;

        /// <summary>
        /// A list of tags on this resource.
        /// </summary>
        [Output("tags")]
        public Output<ImmutableArray<Outputs.DomainsOauth2clientCredentialTag>> Tags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
        /// </summary>
        [Output("tenancyOcid")]
        public Output<string> TenancyOcid { get; private set; } = null!;

        /// <summary>
        /// Controls whether a user can update themselves or not via User related APIs
        /// </summary>
        [Output("urnietfparamsscimschemasoracleidcsextensionselfChangeUser")]
        public Output<Outputs.DomainsOauth2clientCredentialUrnietfparamsscimschemasoracleidcsextensionselfChangeUser> UrnietfparamsscimschemasoracleidcsextensionselfChangeUser { get; private set; } = null!;

        /// <summary>
        /// User linked to oauth2 client credential
        /// </summary>
        [Output("user")]
        public Output<Outputs.DomainsOauth2clientCredentialUser> User { get; private set; } = null!;


        /// <summary>
        /// Create a DomainsOauth2clientCredential resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public DomainsOauth2clientCredential(string name, DomainsOauth2clientCredentialArgs args, CustomResourceOptions? options = null)
            : base("oci:Identity/domainsOauth2clientCredential:DomainsOauth2clientCredential", name, args ?? new DomainsOauth2clientCredentialArgs(), MakeResourceOptions(options, ""))
        {
        }

        private DomainsOauth2clientCredential(string name, Input<string> id, DomainsOauth2clientCredentialState? state = null, CustomResourceOptions? options = null)
            : base("oci:Identity/domainsOauth2clientCredential:DomainsOauth2clientCredential", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing DomainsOauth2clientCredential resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static DomainsOauth2clientCredential Get(string name, Input<string> id, DomainsOauth2clientCredentialState? state = null, CustomResourceOptions? options = null)
        {
            return new DomainsOauth2clientCredential(name, id, state, options);
        }
    }

    public sealed class DomainsOauth2clientCredentialArgs : global::Pulumi.ResourceArgs
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
        /// Description
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// User credential expires on
        /// </summary>
        [Input("expiresOn")]
        public Input<string>? ExpiresOn { get; set; }

        /// <summary>
        /// The basic endpoint for the identity domain
        /// </summary>
        [Input("idcsEndpoint", required: true)]
        public Input<string> IdcsEndpoint { get; set; } = null!;

        /// <summary>
        /// Specifies if secret need to be reset
        /// </summary>
        [Input("isResetSecret")]
        public Input<bool>? IsResetSecret { get; set; }

        /// <summary>
        /// (Updatable) User name
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// User's ocid
        /// </summary>
        [Input("ocid")]
        public Input<string>? Ocid { get; set; }

        /// <summary>
        /// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
        /// </summary>
        [Input("resourceTypeSchemaVersion")]
        public Input<string>? ResourceTypeSchemaVersion { get; set; }

        [Input("schemas", required: true)]
        private InputList<string>? _schemas;

        /// <summary>
        /// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
        /// </summary>
        public InputList<string> Schemas
        {
            get => _schemas ?? (_schemas = new InputList<string>());
            set => _schemas = value;
        }

        [Input("scopes", required: true)]
        private InputList<Inputs.DomainsOauth2clientCredentialScopeArgs>? _scopes;

        /// <summary>
        /// Scopes
        /// </summary>
        public InputList<Inputs.DomainsOauth2clientCredentialScopeArgs> Scopes
        {
            get => _scopes ?? (_scopes = new InputList<Inputs.DomainsOauth2clientCredentialScopeArgs>());
            set => _scopes = value;
        }

        /// <summary>
        /// User credential status
        /// </summary>
        [Input("status")]
        public Input<string>? Status { get; set; }

        [Input("tags")]
        private InputList<Inputs.DomainsOauth2clientCredentialTagArgs>? _tags;

        /// <summary>
        /// A list of tags on this resource.
        /// </summary>
        public InputList<Inputs.DomainsOauth2clientCredentialTagArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.DomainsOauth2clientCredentialTagArgs>());
            set => _tags = value;
        }

        /// <summary>
        /// Controls whether a user can update themselves or not via User related APIs
        /// </summary>
        [Input("urnietfparamsscimschemasoracleidcsextensionselfChangeUser")]
        public Input<Inputs.DomainsOauth2clientCredentialUrnietfparamsscimschemasoracleidcsextensionselfChangeUserArgs>? UrnietfparamsscimschemasoracleidcsextensionselfChangeUser { get; set; }

        /// <summary>
        /// User linked to oauth2 client credential
        /// </summary>
        [Input("user")]
        public Input<Inputs.DomainsOauth2clientCredentialUserArgs>? User { get; set; }

        public DomainsOauth2clientCredentialArgs()
        {
        }
        public static new DomainsOauth2clientCredentialArgs Empty => new DomainsOauth2clientCredentialArgs();
    }

    public sealed class DomainsOauth2clientCredentialState : global::Pulumi.ResourceArgs
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
        /// (Updatable) Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
        /// </summary>
        [Input("compartmentOcid")]
        public Input<string>? CompartmentOcid { get; set; }

        /// <summary>
        /// (Updatable) A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
        /// </summary>
        [Input("deleteInProgress")]
        public Input<bool>? DeleteInProgress { get; set; }

        /// <summary>
        /// Description
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
        /// </summary>
        [Input("domainOcid")]
        public Input<string>? DomainOcid { get; set; }

        /// <summary>
        /// User credential expires on
        /// </summary>
        [Input("expiresOn")]
        public Input<string>? ExpiresOn { get; set; }

        [Input("idcsCreatedBies")]
        private InputList<Inputs.DomainsOauth2clientCredentialIdcsCreatedByGetArgs>? _idcsCreatedBies;

        /// <summary>
        /// (Updatable) The User or App who created the Resource
        /// </summary>
        public InputList<Inputs.DomainsOauth2clientCredentialIdcsCreatedByGetArgs> IdcsCreatedBies
        {
            get => _idcsCreatedBies ?? (_idcsCreatedBies = new InputList<Inputs.DomainsOauth2clientCredentialIdcsCreatedByGetArgs>());
            set => _idcsCreatedBies = value;
        }

        /// <summary>
        /// The basic endpoint for the identity domain
        /// </summary>
        [Input("idcsEndpoint")]
        public Input<string>? IdcsEndpoint { get; set; }

        [Input("idcsLastModifiedBies")]
        private InputList<Inputs.DomainsOauth2clientCredentialIdcsLastModifiedByGetArgs>? _idcsLastModifiedBies;

        /// <summary>
        /// (Updatable) The User or App who modified the Resource
        /// </summary>
        public InputList<Inputs.DomainsOauth2clientCredentialIdcsLastModifiedByGetArgs> IdcsLastModifiedBies
        {
            get => _idcsLastModifiedBies ?? (_idcsLastModifiedBies = new InputList<Inputs.DomainsOauth2clientCredentialIdcsLastModifiedByGetArgs>());
            set => _idcsLastModifiedBies = value;
        }

        /// <summary>
        /// (Updatable) The release number when the resource was upgraded.
        /// </summary>
        [Input("idcsLastUpgradedInRelease")]
        public Input<string>? IdcsLastUpgradedInRelease { get; set; }

        [Input("idcsPreventedOperations")]
        private InputList<string>? _idcsPreventedOperations;

        /// <summary>
        /// (Updatable) Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
        /// </summary>
        public InputList<string> IdcsPreventedOperations
        {
            get => _idcsPreventedOperations ?? (_idcsPreventedOperations = new InputList<string>());
            set => _idcsPreventedOperations = value;
        }

        /// <summary>
        /// Specifies if secret need to be reset
        /// </summary>
        [Input("isResetSecret")]
        public Input<bool>? IsResetSecret { get; set; }

        [Input("metas")]
        private InputList<Inputs.DomainsOauth2clientCredentialMetaGetArgs>? _metas;

        /// <summary>
        /// (Updatable) A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
        /// </summary>
        public InputList<Inputs.DomainsOauth2clientCredentialMetaGetArgs> Metas
        {
            get => _metas ?? (_metas = new InputList<Inputs.DomainsOauth2clientCredentialMetaGetArgs>());
            set => _metas = value;
        }

        /// <summary>
        /// (Updatable) User name
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// User's ocid
        /// </summary>
        [Input("ocid")]
        public Input<string>? Ocid { get; set; }

        /// <summary>
        /// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
        /// </summary>
        [Input("resourceTypeSchemaVersion")]
        public Input<string>? ResourceTypeSchemaVersion { get; set; }

        [Input("schemas")]
        private InputList<string>? _schemas;

        /// <summary>
        /// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
        /// </summary>
        public InputList<string> Schemas
        {
            get => _schemas ?? (_schemas = new InputList<string>());
            set => _schemas = value;
        }

        [Input("scopes")]
        private InputList<Inputs.DomainsOauth2clientCredentialScopeGetArgs>? _scopes;

        /// <summary>
        /// Scopes
        /// </summary>
        public InputList<Inputs.DomainsOauth2clientCredentialScopeGetArgs> Scopes
        {
            get => _scopes ?? (_scopes = new InputList<Inputs.DomainsOauth2clientCredentialScopeGetArgs>());
            set => _scopes = value;
        }

        /// <summary>
        /// User credential status
        /// </summary>
        [Input("status")]
        public Input<string>? Status { get; set; }

        [Input("tags")]
        private InputList<Inputs.DomainsOauth2clientCredentialTagGetArgs>? _tags;

        /// <summary>
        /// A list of tags on this resource.
        /// </summary>
        public InputList<Inputs.DomainsOauth2clientCredentialTagGetArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.DomainsOauth2clientCredentialTagGetArgs>());
            set => _tags = value;
        }

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
        /// </summary>
        [Input("tenancyOcid")]
        public Input<string>? TenancyOcid { get; set; }

        /// <summary>
        /// Controls whether a user can update themselves or not via User related APIs
        /// </summary>
        [Input("urnietfparamsscimschemasoracleidcsextensionselfChangeUser")]
        public Input<Inputs.DomainsOauth2clientCredentialUrnietfparamsscimschemasoracleidcsextensionselfChangeUserGetArgs>? UrnietfparamsscimschemasoracleidcsextensionselfChangeUser { get; set; }

        /// <summary>
        /// User linked to oauth2 client credential
        /// </summary>
        [Input("user")]
        public Input<Inputs.DomainsOauth2clientCredentialUserGetArgs>? User { get; set; }

        public DomainsOauth2clientCredentialState()
        {
        }
        public static new DomainsOauth2clientCredentialState Empty => new DomainsOauth2clientCredentialState();
    }
}