// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Sql Firewall Policies in Oracle Cloud Infrastructure Data Safe service.
 *
 * Retrieves a list of all SQL Firewall policies.
 *
 * The ListSqlFirewallPolicies operation returns only the SQL Firewall policies in the specified `compartmentId`.
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
 * const testSqlFirewallPolicies = oci.DataSafe.getSqlFirewallPolicies({
 *     compartmentId: compartmentId,
 *     accessLevel: sqlFirewallPolicyAccessLevel,
 *     compartmentIdInSubtree: sqlFirewallPolicyCompartmentIdInSubtree,
 *     dbUserName: testUser.name,
 *     displayName: sqlFirewallPolicyDisplayName,
 *     securityPolicyId: testSecurityPolicy.id,
 *     sqlFirewallPolicyId: testSqlFirewallPolicy.id,
 *     state: sqlFirewallPolicyState,
 *     timeCreatedGreaterThanOrEqualTo: sqlFirewallPolicyTimeCreatedGreaterThanOrEqualTo,
 *     timeCreatedLessThan: sqlFirewallPolicyTimeCreatedLessThan,
 *     violationAction: sqlFirewallPolicyViolationAction,
 * });
 * ```
 */
export function getSqlFirewallPolicies(args: GetSqlFirewallPoliciesArgs, opts?: pulumi.InvokeOptions): Promise<GetSqlFirewallPoliciesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataSafe/getSqlFirewallPolicies:getSqlFirewallPolicies", {
        "accessLevel": args.accessLevel,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "dbUserName": args.dbUserName,
        "displayName": args.displayName,
        "filters": args.filters,
        "securityPolicyId": args.securityPolicyId,
        "sqlFirewallPolicyId": args.sqlFirewallPolicyId,
        "state": args.state,
        "timeCreatedGreaterThanOrEqualTo": args.timeCreatedGreaterThanOrEqualTo,
        "timeCreatedLessThan": args.timeCreatedLessThan,
        "violationAction": args.violationAction,
    }, opts);
}

/**
 * A collection of arguments for invoking getSqlFirewallPolicies.
 */
export interface GetSqlFirewallPoliciesArgs {
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
    /**
     * A filter to return only items that match the specified user name.
     */
    dbUserName?: string;
    /**
     * A filter to return only resources that match the specified display name.
     */
    displayName?: string;
    filters?: inputs.DataSafe.GetSqlFirewallPoliciesFilter[];
    /**
     * An optional filter to return only resources that match the specified OCID of the security policy resource.
     */
    securityPolicyId?: string;
    /**
     * An optional filter to return only resources that match the specified OCID of the SQL Firewall policy resource.
     */
    sqlFirewallPolicyId?: string;
    /**
     * The current state of the SQL Firewall policy.
     */
    state?: string;
    /**
     * A filter to return only the resources that were created after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeCreatedGreaterThanOrEqualToQueryParam parameter retrieves all resources created after that date.
     *
     * **Example:** 2016-12-19T16:39:57.600Z
     */
    timeCreatedGreaterThanOrEqualTo?: string;
    /**
     * Search for resources that were created before a specific date. Specifying this parameter corresponding `timeCreatedLessThan` parameter will retrieve all resources created before the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
     *
     * **Example:** 2016-12-19T16:39:57.600Z
     */
    timeCreatedLessThan?: string;
    /**
     * An optional filter to return only resources that match the specified violation action.
     */
    violationAction?: string;
}

/**
 * A collection of values returned by getSqlFirewallPolicies.
 */
export interface GetSqlFirewallPoliciesResult {
    readonly accessLevel?: string;
    /**
     * The OCID of the compartment containing the SQL Firewall policy.
     */
    readonly compartmentId: string;
    readonly compartmentIdInSubtree?: boolean;
    /**
     * The database user name.
     */
    readonly dbUserName?: string;
    /**
     * The display name of the SQL Firewall policy.
     */
    readonly displayName?: string;
    readonly filters?: outputs.DataSafe.GetSqlFirewallPoliciesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The OCID of the security policy corresponding to the SQL Firewall policy.
     */
    readonly securityPolicyId?: string;
    /**
     * The list of sql_firewall_policy_collection.
     */
    readonly sqlFirewallPolicyCollections: outputs.DataSafe.GetSqlFirewallPoliciesSqlFirewallPolicyCollection[];
    readonly sqlFirewallPolicyId?: string;
    /**
     * The current state of the SQL Firewall policy.
     */
    readonly state?: string;
    readonly timeCreatedGreaterThanOrEqualTo?: string;
    readonly timeCreatedLessThan?: string;
    /**
     * Specifies the mode in which the SQL Firewall policy is enabled.
     */
    readonly violationAction?: string;
}
/**
 * This data source provides the list of Sql Firewall Policies in Oracle Cloud Infrastructure Data Safe service.
 *
 * Retrieves a list of all SQL Firewall policies.
 *
 * The ListSqlFirewallPolicies operation returns only the SQL Firewall policies in the specified `compartmentId`.
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
 * const testSqlFirewallPolicies = oci.DataSafe.getSqlFirewallPolicies({
 *     compartmentId: compartmentId,
 *     accessLevel: sqlFirewallPolicyAccessLevel,
 *     compartmentIdInSubtree: sqlFirewallPolicyCompartmentIdInSubtree,
 *     dbUserName: testUser.name,
 *     displayName: sqlFirewallPolicyDisplayName,
 *     securityPolicyId: testSecurityPolicy.id,
 *     sqlFirewallPolicyId: testSqlFirewallPolicy.id,
 *     state: sqlFirewallPolicyState,
 *     timeCreatedGreaterThanOrEqualTo: sqlFirewallPolicyTimeCreatedGreaterThanOrEqualTo,
 *     timeCreatedLessThan: sqlFirewallPolicyTimeCreatedLessThan,
 *     violationAction: sqlFirewallPolicyViolationAction,
 * });
 * ```
 */
export function getSqlFirewallPoliciesOutput(args: GetSqlFirewallPoliciesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetSqlFirewallPoliciesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataSafe/getSqlFirewallPolicies:getSqlFirewallPolicies", {
        "accessLevel": args.accessLevel,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "dbUserName": args.dbUserName,
        "displayName": args.displayName,
        "filters": args.filters,
        "securityPolicyId": args.securityPolicyId,
        "sqlFirewallPolicyId": args.sqlFirewallPolicyId,
        "state": args.state,
        "timeCreatedGreaterThanOrEqualTo": args.timeCreatedGreaterThanOrEqualTo,
        "timeCreatedLessThan": args.timeCreatedLessThan,
        "violationAction": args.violationAction,
    }, opts);
}

/**
 * A collection of arguments for invoking getSqlFirewallPolicies.
 */
export interface GetSqlFirewallPoliciesOutputArgs {
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
    /**
     * A filter to return only items that match the specified user name.
     */
    dbUserName?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the specified display name.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.DataSafe.GetSqlFirewallPoliciesFilterArgs>[]>;
    /**
     * An optional filter to return only resources that match the specified OCID of the security policy resource.
     */
    securityPolicyId?: pulumi.Input<string>;
    /**
     * An optional filter to return only resources that match the specified OCID of the SQL Firewall policy resource.
     */
    sqlFirewallPolicyId?: pulumi.Input<string>;
    /**
     * The current state of the SQL Firewall policy.
     */
    state?: pulumi.Input<string>;
    /**
     * A filter to return only the resources that were created after the specified date and time, as defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Using TimeCreatedGreaterThanOrEqualToQueryParam parameter retrieves all resources created after that date.
     *
     * **Example:** 2016-12-19T16:39:57.600Z
     */
    timeCreatedGreaterThanOrEqualTo?: pulumi.Input<string>;
    /**
     * Search for resources that were created before a specific date. Specifying this parameter corresponding `timeCreatedLessThan` parameter will retrieve all resources created before the specified created date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
     *
     * **Example:** 2016-12-19T16:39:57.600Z
     */
    timeCreatedLessThan?: pulumi.Input<string>;
    /**
     * An optional filter to return only resources that match the specified violation action.
     */
    violationAction?: pulumi.Input<string>;
}
