// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Sql Firewall Allowed Sql Analytics in Oracle Cloud Infrastructure Data Safe service.
 *
 * Returns the aggregation details of all SQL firewall allowed SQL statements.
 *
 * The ListSqlFirewallAllowedSqlAnalytics operation returns the aggregates of the SQL firewall allowed SQL statements in the specified `compartmentId`.
 *
 * The parameter `accessLevel` specifies whether to return only those compartments for which the
 * requestor has INSPECT permissions on at least one resource directly
 * or indirectly (ACCESSIBLE) (the resource can be in a subcompartment) or to return Not Authorized if
 * Principal doesn't have access to even one of the child compartments. This is valid only when
 * `compartmentIdInSubtree` is set to `true`.
 *
 * The parameter `compartmentIdInSubtree` applies when you perform ListSqlFirewallAllowedSqlAnalytics on the
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
 * const testSqlFirewallAllowedSqlAnalytics = oci.DataSafe.getSqlFirewallAllowedSqlAnalytics({
 *     compartmentId: _var.compartment_id,
 *     accessLevel: _var.sql_firewall_allowed_sql_analytic_access_level,
 *     compartmentIdInSubtree: _var.sql_firewall_allowed_sql_analytic_compartment_id_in_subtree,
 *     groupBies: _var.sql_firewall_allowed_sql_analytic_group_by,
 *     scimQuery: _var.sql_firewall_allowed_sql_analytic_scim_query,
 * });
 * ```
 */
export function getSqlFirewallAllowedSqlAnalytics(args: GetSqlFirewallAllowedSqlAnalyticsArgs, opts?: pulumi.InvokeOptions): Promise<GetSqlFirewallAllowedSqlAnalyticsResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataSafe/getSqlFirewallAllowedSqlAnalytics:getSqlFirewallAllowedSqlAnalytics", {
        "accessLevel": args.accessLevel,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "filters": args.filters,
        "groupBies": args.groupBies,
        "scimQuery": args.scimQuery,
    }, opts);
}

/**
 * A collection of arguments for invoking getSqlFirewallAllowedSqlAnalytics.
 */
export interface GetSqlFirewallAllowedSqlAnalyticsArgs {
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
    filters?: inputs.DataSafe.GetSqlFirewallAllowedSqlAnalyticsFilter[];
    /**
     * The group by parameter to summarize the allowed SQL aggregation.
     */
    groupBies?: string[];
    /**
     * The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
     *
     * **Example:** query=(currentUser eq 'SCOTT') and (topLevel eq 'YES')
     */
    scimQuery?: string;
}

/**
 * A collection of values returned by getSqlFirewallAllowedSqlAnalytics.
 */
export interface GetSqlFirewallAllowedSqlAnalyticsResult {
    readonly accessLevel?: string;
    readonly compartmentId: string;
    readonly compartmentIdInSubtree?: boolean;
    readonly filters?: outputs.DataSafe.GetSqlFirewallAllowedSqlAnalyticsFilter[];
    readonly groupBies?: string[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly scimQuery?: string;
    /**
     * The list of sql_firewall_allowed_sql_analytics_collection.
     */
    readonly sqlFirewallAllowedSqlAnalyticsCollections: outputs.DataSafe.GetSqlFirewallAllowedSqlAnalyticsSqlFirewallAllowedSqlAnalyticsCollection[];
}
/**
 * This data source provides the list of Sql Firewall Allowed Sql Analytics in Oracle Cloud Infrastructure Data Safe service.
 *
 * Returns the aggregation details of all SQL firewall allowed SQL statements.
 *
 * The ListSqlFirewallAllowedSqlAnalytics operation returns the aggregates of the SQL firewall allowed SQL statements in the specified `compartmentId`.
 *
 * The parameter `accessLevel` specifies whether to return only those compartments for which the
 * requestor has INSPECT permissions on at least one resource directly
 * or indirectly (ACCESSIBLE) (the resource can be in a subcompartment) or to return Not Authorized if
 * Principal doesn't have access to even one of the child compartments. This is valid only when
 * `compartmentIdInSubtree` is set to `true`.
 *
 * The parameter `compartmentIdInSubtree` applies when you perform ListSqlFirewallAllowedSqlAnalytics on the
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
 * const testSqlFirewallAllowedSqlAnalytics = oci.DataSafe.getSqlFirewallAllowedSqlAnalytics({
 *     compartmentId: _var.compartment_id,
 *     accessLevel: _var.sql_firewall_allowed_sql_analytic_access_level,
 *     compartmentIdInSubtree: _var.sql_firewall_allowed_sql_analytic_compartment_id_in_subtree,
 *     groupBies: _var.sql_firewall_allowed_sql_analytic_group_by,
 *     scimQuery: _var.sql_firewall_allowed_sql_analytic_scim_query,
 * });
 * ```
 */
export function getSqlFirewallAllowedSqlAnalyticsOutput(args: GetSqlFirewallAllowedSqlAnalyticsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetSqlFirewallAllowedSqlAnalyticsResult> {
    return pulumi.output(args).apply((a: any) => getSqlFirewallAllowedSqlAnalytics(a, opts))
}

/**
 * A collection of arguments for invoking getSqlFirewallAllowedSqlAnalytics.
 */
export interface GetSqlFirewallAllowedSqlAnalyticsOutputArgs {
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
    filters?: pulumi.Input<pulumi.Input<inputs.DataSafe.GetSqlFirewallAllowedSqlAnalyticsFilterArgs>[]>;
    /**
     * The group by parameter to summarize the allowed SQL aggregation.
     */
    groupBies?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
     *
     * **Example:** query=(currentUser eq 'SCOTT') and (topLevel eq 'YES')
     */
    scimQuery?: pulumi.Input<string>;
}