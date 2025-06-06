// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Group resource in Oracle Cloud Infrastructure Identity service.
 *
 * Gets the specified group's information.
 *
 * This operation does not return a list of all the users in the group. To do that, use
 * [ListUserGroupMemberships](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/UserGroupMembership/ListUserGroupMemberships) and
 * provide the group's OCID as a query parameter in the request.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testGroup = oci.Identity.getGroup({
 *     groupId: testGroupOciIdentityGroup.id,
 * });
 * ```
 */
export function getGroup(args: GetGroupArgs, opts?: pulumi.InvokeOptions): Promise<GetGroupResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Identity/getGroup:getGroup", {
        "groupId": args.groupId,
    }, opts);
}

/**
 * A collection of arguments for invoking getGroup.
 */
export interface GetGroupArgs {
    /**
     * The OCID of the group.
     */
    groupId: string;
}

/**
 * A collection of values returned by getGroup.
 */
export interface GetGroupResult {
    /**
     * The OCID of the tenancy containing the group.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * The description you assign to the group. Does not have to be unique, and it's changeable.
     */
    readonly description: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    readonly groupId: string;
    /**
     * The OCID of the group.
     */
    readonly id: string;
    /**
     * The detailed status of INACTIVE lifecycleState.
     */
    readonly inactiveState: string;
    /**
     * The name you assign to the group during creation. The name must be unique across all groups in the tenancy and cannot be changed.
     */
    readonly name: string;
    /**
     * The group's current state.
     */
    readonly state: string;
    /**
     * Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     */
    readonly timeCreated: string;
}
/**
 * This data source provides details about a specific Group resource in Oracle Cloud Infrastructure Identity service.
 *
 * Gets the specified group's information.
 *
 * This operation does not return a list of all the users in the group. To do that, use
 * [ListUserGroupMemberships](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/UserGroupMembership/ListUserGroupMemberships) and
 * provide the group's OCID as a query parameter in the request.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testGroup = oci.Identity.getGroup({
 *     groupId: testGroupOciIdentityGroup.id,
 * });
 * ```
 */
export function getGroupOutput(args: GetGroupOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetGroupResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Identity/getGroup:getGroup", {
        "groupId": args.groupId,
    }, opts);
}

/**
 * A collection of arguments for invoking getGroup.
 */
export interface GetGroupOutputArgs {
    /**
     * The OCID of the group.
     */
    groupId: pulumi.Input<string>;
}
