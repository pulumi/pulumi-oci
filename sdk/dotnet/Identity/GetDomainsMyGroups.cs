// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    public static class GetDomainsMyGroups
    {
        /// <summary>
        /// This data source provides the list of My Groups in Oracle Cloud Infrastructure Identity Domains service.
        /// 
        /// Search My Groups
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
        ///     var testMyGroups = Oci.Identity.GetDomainsMyGroups.Invoke(new()
        ///     {
        ///         IdcsEndpoint = data.Oci_identity_domain.Test_domain.Url,
        ///         MyGroupCount = @var.My_group_my_group_count,
        ///         MyGroupFilter = @var.My_group_my_group_filter,
        ///         AttributeSets = new[] {},
        ///         Attributes = "",
        ///         Authorization = @var.My_group_authorization,
        ///         ResourceTypeSchemaVersion = @var.My_group_resource_type_schema_version,
        ///         StartIndex = @var.My_group_start_index,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDomainsMyGroupsResult> InvokeAsync(GetDomainsMyGroupsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDomainsMyGroupsResult>("oci:Identity/getDomainsMyGroups:getDomainsMyGroups", args ?? new GetDomainsMyGroupsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of My Groups in Oracle Cloud Infrastructure Identity Domains service.
        /// 
        /// Search My Groups
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
        ///     var testMyGroups = Oci.Identity.GetDomainsMyGroups.Invoke(new()
        ///     {
        ///         IdcsEndpoint = data.Oci_identity_domain.Test_domain.Url,
        ///         MyGroupCount = @var.My_group_my_group_count,
        ///         MyGroupFilter = @var.My_group_my_group_filter,
        ///         AttributeSets = new[] {},
        ///         Attributes = "",
        ///         Authorization = @var.My_group_authorization,
        ///         ResourceTypeSchemaVersion = @var.My_group_resource_type_schema_version,
        ///         StartIndex = @var.My_group_start_index,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetDomainsMyGroupsResult> Invoke(GetDomainsMyGroupsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDomainsMyGroupsResult>("oci:Identity/getDomainsMyGroups:getDomainsMyGroups", args ?? new GetDomainsMyGroupsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDomainsMyGroupsArgs : global::Pulumi.InvokeArgs
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

        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        /// <summary>
        /// The basic endpoint for the identity domain
        /// </summary>
        [Input("idcsEndpoint", required: true)]
        public string IdcsEndpoint { get; set; } = null!;

        /// <summary>
        /// OPTIONAL. An integer that indicates the desired maximum number of query results per page. 1000 is the largest value that you can use. See the Pagination section of the System for Cross-Domain Identity Management Protocol specification for more information. (Section 3.4.2.4).
        /// </summary>
        [Input("myGroupCount")]
        public int? MyGroupCount { get; set; }

        /// <summary>
        /// OPTIONAL. The filter string that is used to request a subset of resources. The filter string MUST be a valid filter expression. See the Filtering section of the SCIM specification for more information (Section 3.4.2.2). The string should contain at least one condition that each item must match in order to be returned in the search results. Each condition specifies an attribute, an operator, and a value. Conditions within a filter can be connected by logical operators (such as AND and OR). Sets of conditions can be grouped together using parentheses.
        /// </summary>
        [Input("myGroupFilter")]
        public string? MyGroupFilter { get; set; }

        /// <summary>
        /// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
        /// </summary>
        [Input("resourceTypeSchemaVersion")]
        public string? ResourceTypeSchemaVersion { get; set; }

        [Input("sortBy")]
        public string? SortBy { get; set; }

        [Input("sortOrder")]
        public string? SortOrder { get; set; }

        /// <summary>
        /// OPTIONAL. An integer that indicates the 1-based index of the first query result. See the Pagination section of the SCIM specification for more information. (Section 3.4.2.4). The number of results pages to return. The first page is 1. Specify 2 to access the second page of results, and so on.
        /// </summary>
        [Input("startIndex")]
        public int? StartIndex { get; set; }

        public GetDomainsMyGroupsArgs()
        {
        }
        public static new GetDomainsMyGroupsArgs Empty => new GetDomainsMyGroupsArgs();
    }

    public sealed class GetDomainsMyGroupsInvokeArgs : global::Pulumi.InvokeArgs
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

        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The basic endpoint for the identity domain
        /// </summary>
        [Input("idcsEndpoint", required: true)]
        public Input<string> IdcsEndpoint { get; set; } = null!;

        /// <summary>
        /// OPTIONAL. An integer that indicates the desired maximum number of query results per page. 1000 is the largest value that you can use. See the Pagination section of the System for Cross-Domain Identity Management Protocol specification for more information. (Section 3.4.2.4).
        /// </summary>
        [Input("myGroupCount")]
        public Input<int>? MyGroupCount { get; set; }

        /// <summary>
        /// OPTIONAL. The filter string that is used to request a subset of resources. The filter string MUST be a valid filter expression. See the Filtering section of the SCIM specification for more information (Section 3.4.2.2). The string should contain at least one condition that each item must match in order to be returned in the search results. Each condition specifies an attribute, an operator, and a value. Conditions within a filter can be connected by logical operators (such as AND and OR). Sets of conditions can be grouped together using parentheses.
        /// </summary>
        [Input("myGroupFilter")]
        public Input<string>? MyGroupFilter { get; set; }

        /// <summary>
        /// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
        /// </summary>
        [Input("resourceTypeSchemaVersion")]
        public Input<string>? ResourceTypeSchemaVersion { get; set; }

        [Input("sortBy")]
        public Input<string>? SortBy { get; set; }

        [Input("sortOrder")]
        public Input<string>? SortOrder { get; set; }

        /// <summary>
        /// OPTIONAL. An integer that indicates the 1-based index of the first query result. See the Pagination section of the SCIM specification for more information. (Section 3.4.2.4). The number of results pages to return. The first page is 1. Specify 2 to access the second page of results, and so on.
        /// </summary>
        [Input("startIndex")]
        public Input<int>? StartIndex { get; set; }

        public GetDomainsMyGroupsInvokeArgs()
        {
        }
        public static new GetDomainsMyGroupsInvokeArgs Empty => new GetDomainsMyGroupsInvokeArgs();
    }


    [OutputType]
    public sealed class GetDomainsMyGroupsResult
    {
        public readonly ImmutableArray<string> AttributeSets;
        public readonly string? Attributes;
        public readonly string? Authorization;
        public readonly string? CompartmentId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string IdcsEndpoint;
        /// <summary>
        /// The number of resources returned in a list response page. REQUIRED when partial results returned due to pagination.
        /// </summary>
        public readonly int ItemsPerPage;
        public readonly int? MyGroupCount;
        public readonly string? MyGroupFilter;
        /// <summary>
        /// The list of my_groups.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsMyGroupsMyGroupResult> MyGroups;
        public readonly string? ResourceTypeSchemaVersion;
        /// <summary>
        /// The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior. REQUIRED.
        /// </summary>
        public readonly ImmutableArray<string> Schemas;
        public readonly string? SortBy;
        public readonly string? SortOrder;
        /// <summary>
        /// The 1-based index of the first result in the current set of list results.  REQUIRED when partial results returned due to pagination.
        /// </summary>
        public readonly int? StartIndex;
        /// <summary>
        /// The total number of results returned by the list or query operation.  The value may be larger than the number of resources returned such as when returning a single page of results where multiple pages are available. REQUIRED.
        /// </summary>
        public readonly int TotalResults;

        [OutputConstructor]
        private GetDomainsMyGroupsResult(
            ImmutableArray<string> attributeSets,

            string? attributes,

            string? authorization,

            string? compartmentId,

            string id,

            string idcsEndpoint,

            int itemsPerPage,

            int? myGroupCount,

            string? myGroupFilter,

            ImmutableArray<Outputs.GetDomainsMyGroupsMyGroupResult> myGroups,

            string? resourceTypeSchemaVersion,

            ImmutableArray<string> schemas,

            string? sortBy,

            string? sortOrder,

            int? startIndex,

            int totalResults)
        {
            AttributeSets = attributeSets;
            Attributes = attributes;
            Authorization = authorization;
            CompartmentId = compartmentId;
            Id = id;
            IdcsEndpoint = idcsEndpoint;
            ItemsPerPage = itemsPerPage;
            MyGroupCount = myGroupCount;
            MyGroupFilter = myGroupFilter;
            MyGroups = myGroups;
            ResourceTypeSchemaVersion = resourceTypeSchemaVersion;
            Schemas = schemas;
            SortBy = sortBy;
            SortOrder = sortOrder;
            StartIndex = startIndex;
            TotalResults = totalResults;
        }
    }
}