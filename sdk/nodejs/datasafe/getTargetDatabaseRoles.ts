// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Target Database Roles in Oracle Cloud Infrastructure Data Safe service.
 *
 * Returns a list of role metadata objects.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testTargetDatabaseRoles = oci.DataSafe.getTargetDatabaseRoles({
 *     targetDatabaseId: testTargetDatabase.id,
 *     authenticationType: targetDatabaseRoleAuthenticationType,
 *     isOracleMaintained: targetDatabaseRoleIsOracleMaintained,
 *     roleNames: targetDatabaseRoleRoleName,
 *     roleNameContains: targetDatabaseRoleRoleNameContains,
 * });
 * ```
 */
export function getTargetDatabaseRoles(args: GetTargetDatabaseRolesArgs, opts?: pulumi.InvokeOptions): Promise<GetTargetDatabaseRolesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataSafe/getTargetDatabaseRoles:getTargetDatabaseRoles", {
        "authenticationType": args.authenticationType,
        "filters": args.filters,
        "isOracleMaintained": args.isOracleMaintained,
        "roleNameContains": args.roleNameContains,
        "roleNames": args.roleNames,
        "targetDatabaseId": args.targetDatabaseId,
    }, opts);
}

/**
 * A collection of arguments for invoking getTargetDatabaseRoles.
 */
export interface GetTargetDatabaseRolesArgs {
    /**
     * A filter to return roles based on authentication type.
     */
    authenticationType?: string;
    filters?: inputs.DataSafe.GetTargetDatabaseRolesFilter[];
    /**
     * A filter to return roles based on whether they are maintained by oracle or not.
     */
    isOracleMaintained?: boolean;
    /**
     * A filter to return only items if role name contains a specific string.
     */
    roleNameContains?: string;
    /**
     * A filter to return only a specific role based on role name.
     */
    roleNames?: string[];
    /**
     * The OCID of the Data Safe target database.
     */
    targetDatabaseId: string;
}

/**
 * A collection of values returned by getTargetDatabaseRoles.
 */
export interface GetTargetDatabaseRolesResult {
    /**
     * Type of authentication.
     */
    readonly authenticationType?: string;
    readonly filters?: outputs.DataSafe.GetTargetDatabaseRolesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Is the role oracle maintained.
     */
    readonly isOracleMaintained?: boolean;
    readonly roleNameContains?: string;
    /**
     * The name of the role.
     */
    readonly roleNames?: string[];
    /**
     * The list of roles.
     */
    readonly roles: outputs.DataSafe.GetTargetDatabaseRolesRole[];
    readonly targetDatabaseId: string;
}
/**
 * This data source provides the list of Target Database Roles in Oracle Cloud Infrastructure Data Safe service.
 *
 * Returns a list of role metadata objects.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testTargetDatabaseRoles = oci.DataSafe.getTargetDatabaseRoles({
 *     targetDatabaseId: testTargetDatabase.id,
 *     authenticationType: targetDatabaseRoleAuthenticationType,
 *     isOracleMaintained: targetDatabaseRoleIsOracleMaintained,
 *     roleNames: targetDatabaseRoleRoleName,
 *     roleNameContains: targetDatabaseRoleRoleNameContains,
 * });
 * ```
 */
export function getTargetDatabaseRolesOutput(args: GetTargetDatabaseRolesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetTargetDatabaseRolesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataSafe/getTargetDatabaseRoles:getTargetDatabaseRoles", {
        "authenticationType": args.authenticationType,
        "filters": args.filters,
        "isOracleMaintained": args.isOracleMaintained,
        "roleNameContains": args.roleNameContains,
        "roleNames": args.roleNames,
        "targetDatabaseId": args.targetDatabaseId,
    }, opts);
}

/**
 * A collection of arguments for invoking getTargetDatabaseRoles.
 */
export interface GetTargetDatabaseRolesOutputArgs {
    /**
     * A filter to return roles based on authentication type.
     */
    authenticationType?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.DataSafe.GetTargetDatabaseRolesFilterArgs>[]>;
    /**
     * A filter to return roles based on whether they are maintained by oracle or not.
     */
    isOracleMaintained?: pulumi.Input<boolean>;
    /**
     * A filter to return only items if role name contains a specific string.
     */
    roleNameContains?: pulumi.Input<string>;
    /**
     * A filter to return only a specific role based on role name.
     */
    roleNames?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The OCID of the Data Safe target database.
     */
    targetDatabaseId: pulumi.Input<string>;
}
