// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Sql Firewall Allowed Sqls in Oracle Cloud Infrastructure Data Safe service.
 *
 * Retrieves a list of all SQL Firewall allowed SQL statements.
 *
 * The ListSqlFirewallAllowedSqls operation returns only the SQL Firewall allowed SQL statements in the specified `compartmentId`.
 *
 * The parameter `accessLevel` specifies whether to return only those compartments for which the
 * requestor has INSPECT permissions on at least one resource directly
 * or indirectly (ACCESSIBLE) (the resource can be in a subcompartment) or to return Not Authorized if
 * Principal doesn't have access to even one of the child compartments. This is valid only when
 * `compartmentIdInSubtree` is set to `true`.
 *
 * The parameter `compartmentIdInSubtree` applies when you perform ListSqlFirewallPolicies on the
 * `compartmentId` passed and when it is set to true, the entire hierarchy of compartments can be returned.
 * To get a full list of all compartments and subcompartments in the tenancy (root compartment),
 * set the parameter `compartmentIdInSubtree` to true and `accessLevel` to ACCESSIBLE.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSqlFirewallAllowedSqls = oci.DataSafe.getSqlFirewallAllowedSqls({
 *     compartmentId: compartmentId,
 *     accessLevel: sqlFirewallAllowedSqlAccessLevel,
 *     compartmentIdInSubtree: sqlFirewallAllowedSqlCompartmentIdInSubtree,
 *     scimQuery: sqlFirewallAllowedSqlScimQuery,
 * });
 * ```
 */
export function getSqlFirewallAllowedSqls(args: GetSqlFirewallAllowedSqlsArgs, opts?: pulumi.InvokeOptions): Promise<GetSqlFirewallAllowedSqlsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataSafe/getSqlFirewallAllowedSqls:getSqlFirewallAllowedSqls", {
        "accessLevel": args.accessLevel,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "filters": args.filters,
        "scimQuery": args.scimQuery,
    }, opts);
}

/**
 * A collection of arguments for invoking getSqlFirewallAllowedSqls.
 */
export interface GetSqlFirewallAllowedSqlsArgs {
    /**
     * Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     */
    accessLevel?: string;
    /**
     * A filter to return only resources that match the specified compartment OCID.
     */
    compartmentId: string;
    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
     */
    compartmentIdInSubtree?: boolean;
    filters?: inputs.DataSafe.GetSqlFirewallAllowedSqlsFilter[];
    /**
     * The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
     *
     * **Example:** query=(currentUser eq 'SCOTT') and (topLevel eq 'YES')
     */
    scimQuery?: string;
}

/**
 * A collection of values returned by getSqlFirewallAllowedSqls.
 */
export interface GetSqlFirewallAllowedSqlsResult {
    readonly accessLevel?: string;
    /**
     * The OCID of the compartment containing the SQL Firewall allowed SQL.
     */
    readonly compartmentId: string;
    readonly compartmentIdInSubtree?: boolean;
    readonly filters?: outputs.DataSafe.GetSqlFirewallAllowedSqlsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly scimQuery?: string;
    /**
     * The list of sql_firewall_allowed_sql_collection.
     */
    readonly sqlFirewallAllowedSqlCollections: outputs.DataSafe.GetSqlFirewallAllowedSqlsSqlFirewallAllowedSqlCollection[];
}
/**
 * This data source provides the list of Sql Firewall Allowed Sqls in Oracle Cloud Infrastructure Data Safe service.
 *
 * Retrieves a list of all SQL Firewall allowed SQL statements.
 *
 * The ListSqlFirewallAllowedSqls operation returns only the SQL Firewall allowed SQL statements in the specified `compartmentId`.
 *
 * The parameter `accessLevel` specifies whether to return only those compartments for which the
 * requestor has INSPECT permissions on at least one resource directly
 * or indirectly (ACCESSIBLE) (the resource can be in a subcompartment) or to return Not Authorized if
 * Principal doesn't have access to even one of the child compartments. This is valid only when
 * `compartmentIdInSubtree` is set to `true`.
 *
 * The parameter `compartmentIdInSubtree` applies when you perform ListSqlFirewallPolicies on the
 * `compartmentId` passed and when it is set to true, the entire hierarchy of compartments can be returned.
 * To get a full list of all compartments and subcompartments in the tenancy (root compartment),
 * set the parameter `compartmentIdInSubtree` to true and `accessLevel` to ACCESSIBLE.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSqlFirewallAllowedSqls = oci.DataSafe.getSqlFirewallAllowedSqls({
 *     compartmentId: compartmentId,
 *     accessLevel: sqlFirewallAllowedSqlAccessLevel,
 *     compartmentIdInSubtree: sqlFirewallAllowedSqlCompartmentIdInSubtree,
 *     scimQuery: sqlFirewallAllowedSqlScimQuery,
 * });
 * ```
 */
export function getSqlFirewallAllowedSqlsOutput(args: GetSqlFirewallAllowedSqlsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetSqlFirewallAllowedSqlsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataSafe/getSqlFirewallAllowedSqls:getSqlFirewallAllowedSqls", {
        "accessLevel": args.accessLevel,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "filters": args.filters,
        "scimQuery": args.scimQuery,
    }, opts);
}

/**
 * A collection of arguments for invoking getSqlFirewallAllowedSqls.
 */
export interface GetSqlFirewallAllowedSqlsOutputArgs {
    /**
     * Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     */
    accessLevel?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the specified compartment OCID.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
     */
    compartmentIdInSubtree?: pulumi.Input<boolean>;
    filters?: pulumi.Input<pulumi.Input<inputs.DataSafe.GetSqlFirewallAllowedSqlsFilterArgs>[]>;
    /**
     * The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
     *
     * **Example:** query=(currentUser eq 'SCOTT') and (topLevel eq 'YES')
     */
    scimQuery?: pulumi.Input<string>;
}
