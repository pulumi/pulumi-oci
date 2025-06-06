// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Sensitive Type Groups in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets a list of sensitive type groups based on the specified query parameters.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSensitiveTypeGroups = oci.DataSafe.getSensitiveTypeGroups({
 *     compartmentId: compartmentId,
 *     accessLevel: sensitiveTypeGroupAccessLevel,
 *     compartmentIdInSubtree: sensitiveTypeGroupCompartmentIdInSubtree,
 *     displayName: sensitiveTypeGroupDisplayName,
 *     sensitiveTypeGroupId: testSensitiveTypeGroup.id,
 *     state: sensitiveTypeGroupState,
 *     timeCreatedGreaterThanOrEqualTo: sensitiveTypeGroupTimeCreatedGreaterThanOrEqualTo,
 *     timeCreatedLessThan: sensitiveTypeGroupTimeCreatedLessThan,
 * });
 * ```
 */
export function getSensitiveTypeGroups(args: GetSensitiveTypeGroupsArgs, opts?: pulumi.InvokeOptions): Promise<GetSensitiveTypeGroupsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataSafe/getSensitiveTypeGroups:getSensitiveTypeGroups", {
        "accessLevel": args.accessLevel,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "displayName": args.displayName,
        "filters": args.filters,
        "sensitiveTypeGroupId": args.sensitiveTypeGroupId,
        "state": args.state,
        "timeCreatedGreaterThanOrEqualTo": args.timeCreatedGreaterThanOrEqualTo,
        "timeCreatedLessThan": args.timeCreatedLessThan,
    }, opts);
}

/**
 * A collection of arguments for invoking getSensitiveTypeGroups.
 */
export interface GetSensitiveTypeGroupsArgs {
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
     * A filter to return only resources that match the specified display name.
     */
    displayName?: string;
    filters?: inputs.DataSafe.GetSensitiveTypeGroupsFilter[];
    /**
     * An optional filter to return only resources that match the specified OCID of the sensitive type group resource.
     */
    sensitiveTypeGroupId?: string;
    /**
     * A filter to return only the resources that match the specified lifecycle state.
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
}

/**
 * A collection of values returned by getSensitiveTypeGroups.
 */
export interface GetSensitiveTypeGroupsResult {
    readonly accessLevel?: string;
    /**
     * The OCID of the compartment that contains the sensitive type group.
     */
    readonly compartmentId: string;
    readonly compartmentIdInSubtree?: boolean;
    /**
     * The display name of the sensitive type group.
     */
    readonly displayName?: string;
    readonly filters?: outputs.DataSafe.GetSensitiveTypeGroupsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of sensitive_type_group_collection.
     */
    readonly sensitiveTypeGroupCollections: outputs.DataSafe.GetSensitiveTypeGroupsSensitiveTypeGroupCollection[];
    readonly sensitiveTypeGroupId?: string;
    /**
     * The current state of the sensitive type group.
     */
    readonly state?: string;
    readonly timeCreatedGreaterThanOrEqualTo?: string;
    readonly timeCreatedLessThan?: string;
}
/**
 * This data source provides the list of Sensitive Type Groups in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets a list of sensitive type groups based on the specified query parameters.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSensitiveTypeGroups = oci.DataSafe.getSensitiveTypeGroups({
 *     compartmentId: compartmentId,
 *     accessLevel: sensitiveTypeGroupAccessLevel,
 *     compartmentIdInSubtree: sensitiveTypeGroupCompartmentIdInSubtree,
 *     displayName: sensitiveTypeGroupDisplayName,
 *     sensitiveTypeGroupId: testSensitiveTypeGroup.id,
 *     state: sensitiveTypeGroupState,
 *     timeCreatedGreaterThanOrEqualTo: sensitiveTypeGroupTimeCreatedGreaterThanOrEqualTo,
 *     timeCreatedLessThan: sensitiveTypeGroupTimeCreatedLessThan,
 * });
 * ```
 */
export function getSensitiveTypeGroupsOutput(args: GetSensitiveTypeGroupsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetSensitiveTypeGroupsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataSafe/getSensitiveTypeGroups:getSensitiveTypeGroups", {
        "accessLevel": args.accessLevel,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "displayName": args.displayName,
        "filters": args.filters,
        "sensitiveTypeGroupId": args.sensitiveTypeGroupId,
        "state": args.state,
        "timeCreatedGreaterThanOrEqualTo": args.timeCreatedGreaterThanOrEqualTo,
        "timeCreatedLessThan": args.timeCreatedLessThan,
    }, opts);
}

/**
 * A collection of arguments for invoking getSensitiveTypeGroups.
 */
export interface GetSensitiveTypeGroupsOutputArgs {
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
     * A filter to return only resources that match the specified display name.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.DataSafe.GetSensitiveTypeGroupsFilterArgs>[]>;
    /**
     * An optional filter to return only resources that match the specified OCID of the sensitive type group resource.
     */
    sensitiveTypeGroupId?: pulumi.Input<string>;
    /**
     * A filter to return only the resources that match the specified lifecycle state.
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
}
