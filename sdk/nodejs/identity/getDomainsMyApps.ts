// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of My Apps in Oracle Cloud Infrastructure Identity Domains service.
 *
 * Search My Apps
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMyApps = oci.Identity.getDomainsMyApps({
 *     idcsEndpoint: data.oci_identity_domain.test_domain.url,
 *     myAppCount: _var.my_app_my_app_count,
 *     myAppFilter: _var.my_app_my_app_filter,
 *     authorization: _var.my_app_authorization,
 *     resourceTypeSchemaVersion: _var.my_app_resource_type_schema_version,
 *     startIndex: _var.my_app_start_index,
 * });
 * ```
 */
export function getDomainsMyApps(args: GetDomainsMyAppsArgs, opts?: pulumi.InvokeOptions): Promise<GetDomainsMyAppsResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Identity/getDomainsMyApps:getDomainsMyApps", {
        "authorization": args.authorization,
        "compartmentId": args.compartmentId,
        "idcsEndpoint": args.idcsEndpoint,
        "myAppCount": args.myAppCount,
        "myAppFilter": args.myAppFilter,
        "resourceTypeSchemaVersion": args.resourceTypeSchemaVersion,
        "sortBy": args.sortBy,
        "sortOrder": args.sortOrder,
        "startIndex": args.startIndex,
    }, opts);
}

/**
 * A collection of arguments for invoking getDomainsMyApps.
 */
export interface GetDomainsMyAppsArgs {
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
    myAppCount?: number;
    /**
     * OPTIONAL. The filter string that is used to request a subset of resources. The filter string MUST be a valid filter expression. See the Filtering section of the SCIM specification for more information (Section 3.4.2.2). The string should contain at least one condition that each item must match in order to be returned in the search results. Each condition specifies an attribute, an operator, and a value. Conditions within a filter can be connected by logical operators (such as AND and OR). Sets of conditions can be grouped together using parentheses.
     */
    myAppFilter?: string;
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
 * A collection of values returned by getDomainsMyApps.
 */
export interface GetDomainsMyAppsResult {
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
    readonly myAppCount?: number;
    readonly myAppFilter?: string;
    /**
     * The list of my_apps.
     */
    readonly myApps: outputs.Identity.GetDomainsMyAppsMyApp[];
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
 * This data source provides the list of My Apps in Oracle Cloud Infrastructure Identity Domains service.
 *
 * Search My Apps
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMyApps = oci.Identity.getDomainsMyApps({
 *     idcsEndpoint: data.oci_identity_domain.test_domain.url,
 *     myAppCount: _var.my_app_my_app_count,
 *     myAppFilter: _var.my_app_my_app_filter,
 *     authorization: _var.my_app_authorization,
 *     resourceTypeSchemaVersion: _var.my_app_resource_type_schema_version,
 *     startIndex: _var.my_app_start_index,
 * });
 * ```
 */
export function getDomainsMyAppsOutput(args: GetDomainsMyAppsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetDomainsMyAppsResult> {
    return pulumi.output(args).apply((a: any) => getDomainsMyApps(a, opts))
}

/**
 * A collection of arguments for invoking getDomainsMyApps.
 */
export interface GetDomainsMyAppsOutputArgs {
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
    myAppCount?: pulumi.Input<number>;
    /**
     * OPTIONAL. The filter string that is used to request a subset of resources. The filter string MUST be a valid filter expression. See the Filtering section of the SCIM specification for more information (Section 3.4.2.2). The string should contain at least one condition that each item must match in order to be returned in the search results. Each condition specifies an attribute, an operator, and a value. Conditions within a filter can be connected by logical operators (such as AND and OR). Sets of conditions can be grouped together using parentheses.
     */
    myAppFilter?: pulumi.Input<string>;
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