// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class GetDomainsDynamicResourceGroupsDynamicResourceGroupResult
    {
        /// <summary>
        /// A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
        /// </summary>
        public readonly ImmutableArray<string> AttributeSets;
        /// <summary>
        /// A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
        /// </summary>
        public readonly string Attributes;
        /// <summary>
        /// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
        /// </summary>
        public readonly string Authorization;
        /// <summary>
        /// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string CompartmentOcid;
        /// <summary>
        /// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
        /// </summary>
        public readonly bool DeleteInProgress;
        /// <summary>
        /// text that explains the purpose of this Dynamic Resource Group
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// User-friendly, mutable identifier
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string DomainOcid;
        /// <summary>
        /// A list of appRoles that are currently granted to this Dynamic Resource Group.  The Identity service will assert these AppRoles for any resource that satisfies the matching-rule of this DynamicResourceGroup.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsDynamicResourceGroupsDynamicResourceGroupDynamicGroupAppRoleResult> DynamicGroupAppRoles;
        /// <summary>
        /// Grants assigned to group
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsDynamicResourceGroupsDynamicResourceGroupGrantResult> Grants;
        /// <summary>
        /// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The User or App who created the Resource
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsDynamicResourceGroupsDynamicResourceGroupIdcsCreatedByResult> IdcsCreatedBies;
        /// <summary>
        /// The basic endpoint for the identity domain
        /// </summary>
        public readonly string IdcsEndpoint;
        /// <summary>
        /// The User or App who modified the Resource
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsDynamicResourceGroupsDynamicResourceGroupIdcsLastModifiedByResult> IdcsLastModifiedBies;
        /// <summary>
        /// The release number when the resource was upgraded.
        /// </summary>
        public readonly string IdcsLastUpgradedInRelease;
        /// <summary>
        /// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
        /// </summary>
        public readonly ImmutableArray<string> IdcsPreventedOperations;
        /// <summary>
        /// Store as a string the matching-rule for this Dynamic Resource Group. This may match any number of Apps in this Domain, as well as matching any number of Oracle Cloud Infrastructure resources that are not in any Domain but that are in the Oracle Cloud Infrastructure Compartment that contains this Domain.
        /// </summary>
        public readonly string MatchingRule;
        /// <summary>
        /// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsDynamicResourceGroupsDynamicResourceGroupMetaResult> Metas;
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
        /// A list of tags on this resource.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsDynamicResourceGroupsDynamicResourceGroupTagResult> Tags;
        /// <summary>
        /// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string TenancyOcid;
        /// <summary>
        /// Oracle Cloud Infrastructure Tags.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsDynamicResourceGroupsDynamicResourceGroupUrnietfparamsscimschemasoracleidcsextensionOciTagResult> UrnietfparamsscimschemasoracleidcsextensionOciTags;

        [OutputConstructor]
        private GetDomainsDynamicResourceGroupsDynamicResourceGroupResult(
            ImmutableArray<string> attributeSets,

            string attributes,

            string authorization,

            string compartmentOcid,

            bool deleteInProgress,

            string description,

            string displayName,

            string domainOcid,

            ImmutableArray<Outputs.GetDomainsDynamicResourceGroupsDynamicResourceGroupDynamicGroupAppRoleResult> dynamicGroupAppRoles,

            ImmutableArray<Outputs.GetDomainsDynamicResourceGroupsDynamicResourceGroupGrantResult> grants,

            string id,

            ImmutableArray<Outputs.GetDomainsDynamicResourceGroupsDynamicResourceGroupIdcsCreatedByResult> idcsCreatedBies,

            string idcsEndpoint,

            ImmutableArray<Outputs.GetDomainsDynamicResourceGroupsDynamicResourceGroupIdcsLastModifiedByResult> idcsLastModifiedBies,

            string idcsLastUpgradedInRelease,

            ImmutableArray<string> idcsPreventedOperations,

            string matchingRule,

            ImmutableArray<Outputs.GetDomainsDynamicResourceGroupsDynamicResourceGroupMetaResult> metas,

            string ocid,

            string resourceTypeSchemaVersion,

            ImmutableArray<string> schemas,

            ImmutableArray<Outputs.GetDomainsDynamicResourceGroupsDynamicResourceGroupTagResult> tags,

            string tenancyOcid,

            ImmutableArray<Outputs.GetDomainsDynamicResourceGroupsDynamicResourceGroupUrnietfparamsscimschemasoracleidcsextensionOciTagResult> urnietfparamsscimschemasoracleidcsextensionOciTags)
        {
            AttributeSets = attributeSets;
            Attributes = attributes;
            Authorization = authorization;
            CompartmentOcid = compartmentOcid;
            DeleteInProgress = deleteInProgress;
            Description = description;
            DisplayName = displayName;
            DomainOcid = domainOcid;
            DynamicGroupAppRoles = dynamicGroupAppRoles;
            Grants = grants;
            Id = id;
            IdcsCreatedBies = idcsCreatedBies;
            IdcsEndpoint = idcsEndpoint;
            IdcsLastModifiedBies = idcsLastModifiedBies;
            IdcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            IdcsPreventedOperations = idcsPreventedOperations;
            MatchingRule = matchingRule;
            Metas = metas;
            Ocid = ocid;
            ResourceTypeSchemaVersion = resourceTypeSchemaVersion;
            Schemas = schemas;
            Tags = tags;
            TenancyOcid = tenancyOcid;
            UrnietfparamsscimschemasoracleidcsextensionOciTags = urnietfparamsscimschemasoracleidcsextensionOciTags;
        }
    }
}