// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Resource Type Schema Attributes in Oracle Cloud Infrastructure Identity Domains service.
 *
 * Search Resource Type Schema Attributes
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testResourceTypeSchemaAttributes = oci.Identity.getDomainsResourceTypeSchemaAttributes({
 *     idcsEndpoint: data.oci_identity_domain.test_domain.url,
 *     resourceTypeSchemaAttributeCount: _var.resource_type_schema_attribute_resource_type_schema_attribute_count,
 *     resourceTypeSchemaAttributeFilter: _var.resource_type_schema_attribute_resource_type_schema_attribute_filter,
 *     attributeSets: ["all"],
 *     attributes: "",
 *     authorization: _var.resource_type_schema_attribute_authorization,
 *     resourceTypeSchemaVersion: _var.resource_type_schema_attribute_resource_type_schema_version,
 *     startIndex: _var.resource_type_schema_attribute_start_index,
 * });
 * ```
 */
export function getDomainsResourceTypeSchemaAttributes(args: GetDomainsResourceTypeSchemaAttributesArgs, opts?: pulumi.InvokeOptions): Promise<GetDomainsResourceTypeSchemaAttributesResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Identity/getDomainsResourceTypeSchemaAttributes:getDomainsResourceTypeSchemaAttributes", {
        "attributeSets": args.attributeSets,
        "attributes": args.attributes,
        "authorization": args.authorization,
        "compartmentId": args.compartmentId,
        "idcsEndpoint": args.idcsEndpoint,
        "resourceTypeSchemaAttributeCount": args.resourceTypeSchemaAttributeCount,
        "resourceTypeSchemaAttributeFilter": args.resourceTypeSchemaAttributeFilter,
        "resourceTypeSchemaVersion": args.resourceTypeSchemaVersion,
        "sortBy": args.sortBy,
        "sortOrder": args.sortOrder,
        "startIndex": args.startIndex,
    }, opts);
}

/**
 * A collection of arguments for invoking getDomainsResourceTypeSchemaAttributes.
 */
export interface GetDomainsResourceTypeSchemaAttributesArgs {
    /**
     * A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
     */
    attributeSets?: string[];
    /**
     * A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
     */
    attributes?: string;
    /**
     * The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     */
    authorization?: string;
    compartmentId?: string;
    /**
     * The basic endpoint for the identity domain
     */
    idcsEndpoint: string;
    /**
     * OPTIONAL. An integer that indicates the desired maximum number of query results per page. 1000 is the largest value that you can use. See the Pagination section of the System for Cross-Domain Identity Management Protocol specification for more information. (Section 3.4.2.4).
     */
    resourceTypeSchemaAttributeCount?: number;
    /**
     * OPTIONAL. The filter string that is used to request a subset of resources. The filter string MUST be a valid filter expression. See the Filtering section of the SCIM specification for more information (Section 3.4.2.2). The string should contain at least one condition that each item must match in order to be returned in the search results. Each condition specifies an attribute, an operator, and a value. Conditions within a filter can be connected by logical operators (such as AND and OR). Sets of conditions can be grouped together using parentheses.
     */
    resourceTypeSchemaAttributeFilter?: string;
    /**
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     */
    resourceTypeSchemaVersion?: string;
    sortBy?: string;
    sortOrder?: string;
    /**
     * OPTIONAL. An integer that indicates the 1-based index of the first query result. See the Pagination section of the SCIM specification for more information. (Section 3.4.2.4). The number of results pages to return. The first page is 1. Specify 2 to access the second page of results, and so on.
     */
    startIndex?: number;
}

/**
 * A collection of values returned by getDomainsResourceTypeSchemaAttributes.
 */
export interface GetDomainsResourceTypeSchemaAttributesResult {
    readonly attributeSets?: string[];
    readonly attributes?: string;
    readonly authorization?: string;
    readonly compartmentId?: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly idcsEndpoint: string;
    /**
     * The number of resources returned in a list response page. REQUIRED when partial results returned due to pagination.
     */
    readonly itemsPerPage: number;
    readonly resourceTypeSchemaAttributeCount?: number;
    readonly resourceTypeSchemaAttributeFilter?: string;
    /**
     * The list of resource_type_schema_attributes.
     */
    readonly resourceTypeSchemaAttributes: outputs.Identity.GetDomainsResourceTypeSchemaAttributesResourceTypeSchemaAttribute[];
    readonly resourceTypeSchemaVersion?: string;
    /**
     * The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior. REQUIRED.
     */
    readonly schemas: string[];
    readonly sortBy?: string;
    readonly sortOrder?: string;
    /**
     * The 1-based index of the first result in the current set of list results.  REQUIRED when partial results returned due to pagination.
     */
    readonly startIndex?: number;
    /**
     * The total number of results returned by the list or query operation.  The value may be larger than the number of resources returned such as when returning a single page of results where multiple pages are available. REQUIRED.
     */
    readonly totalResults: number;
}
/**
 * This data source provides the list of Resource Type Schema Attributes in Oracle Cloud Infrastructure Identity Domains service.
 *
 * Search Resource Type Schema Attributes
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testResourceTypeSchemaAttributes = oci.Identity.getDomainsResourceTypeSchemaAttributes({
 *     idcsEndpoint: data.oci_identity_domain.test_domain.url,
 *     resourceTypeSchemaAttributeCount: _var.resource_type_schema_attribute_resource_type_schema_attribute_count,
 *     resourceTypeSchemaAttributeFilter: _var.resource_type_schema_attribute_resource_type_schema_attribute_filter,
 *     attributeSets: ["all"],
 *     attributes: "",
 *     authorization: _var.resource_type_schema_attribute_authorization,
 *     resourceTypeSchemaVersion: _var.resource_type_schema_attribute_resource_type_schema_version,
 *     startIndex: _var.resource_type_schema_attribute_start_index,
 * });
 * ```
 */
export function getDomainsResourceTypeSchemaAttributesOutput(args: GetDomainsResourceTypeSchemaAttributesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetDomainsResourceTypeSchemaAttributesResult> {
    return pulumi.output(args).apply((a: any) => getDomainsResourceTypeSchemaAttributes(a, opts))
}

/**
 * A collection of arguments for invoking getDomainsResourceTypeSchemaAttributes.
 */
export interface GetDomainsResourceTypeSchemaAttributesOutputArgs {
    /**
     * A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
     */
    attributeSets?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
     */
    attributes?: pulumi.Input<string>;
    /**
     * The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     */
    authorization?: pulumi.Input<string>;
    compartmentId?: pulumi.Input<string>;
    /**
     * The basic endpoint for the identity domain
     */
    idcsEndpoint: pulumi.Input<string>;
    /**
     * OPTIONAL. An integer that indicates the desired maximum number of query results per page. 1000 is the largest value that you can use. See the Pagination section of the System for Cross-Domain Identity Management Protocol specification for more information. (Section 3.4.2.4).
     */
    resourceTypeSchemaAttributeCount?: pulumi.Input<number>;
    /**
     * OPTIONAL. The filter string that is used to request a subset of resources. The filter string MUST be a valid filter expression. See the Filtering section of the SCIM specification for more information (Section 3.4.2.2). The string should contain at least one condition that each item must match in order to be returned in the search results. Each condition specifies an attribute, an operator, and a value. Conditions within a filter can be connected by logical operators (such as AND and OR). Sets of conditions can be grouped together using parentheses.
     */
    resourceTypeSchemaAttributeFilter?: pulumi.Input<string>;
    /**
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     */
    resourceTypeSchemaVersion?: pulumi.Input<string>;
    sortBy?: pulumi.Input<string>;
    sortOrder?: pulumi.Input<string>;
    /**
     * OPTIONAL. An integer that indicates the 1-based index of the first query result. See the Pagination section of the SCIM specification for more information. (Section 3.4.2.4). The number of results pages to return. The first page is 1. Specify 2 to access the second page of results, and so on.
     */
    startIndex?: pulumi.Input<number>;
}