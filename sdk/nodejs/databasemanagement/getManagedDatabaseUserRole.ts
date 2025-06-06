// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Managed Database User Role resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Gets the list of roles granted to a specific user.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedDatabaseUserRole = oci.DatabaseManagement.getManagedDatabaseUserRole({
 *     managedDatabaseId: testManagedDatabase.id,
 *     userName: testUser.name,
 *     name: managedDatabaseUserRoleName,
 * });
 * ```
 */
export function getManagedDatabaseUserRole(args: GetManagedDatabaseUserRoleArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedDatabaseUserRoleResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DatabaseManagement/getManagedDatabaseUserRole:getManagedDatabaseUserRole", {
        "managedDatabaseId": args.managedDatabaseId,
        "name": args.name,
        "userName": args.userName,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedDatabaseUserRole.
 */
export interface GetManagedDatabaseUserRoleArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: string;
    /**
     * A filter to return only resources that match the entire name.
     */
    name?: string;
    /**
     * The name of the user whose details are to be viewed.
     */
    userName: string;
}

/**
 * A collection of values returned by getManagedDatabaseUserRole.
 */
export interface GetManagedDatabaseUserRoleResult {
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * An array of roles.
     */
    readonly items: outputs.DatabaseManagement.GetManagedDatabaseUserRoleItem[];
    readonly managedDatabaseId: string;
    /**
     * The name of the role granted to the user.
     */
    readonly name?: string;
    readonly userName: string;
}
/**
 * This data source provides details about a specific Managed Database User Role resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Gets the list of roles granted to a specific user.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedDatabaseUserRole = oci.DatabaseManagement.getManagedDatabaseUserRole({
 *     managedDatabaseId: testManagedDatabase.id,
 *     userName: testUser.name,
 *     name: managedDatabaseUserRoleName,
 * });
 * ```
 */
export function getManagedDatabaseUserRoleOutput(args: GetManagedDatabaseUserRoleOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetManagedDatabaseUserRoleResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DatabaseManagement/getManagedDatabaseUserRole:getManagedDatabaseUserRole", {
        "managedDatabaseId": args.managedDatabaseId,
        "name": args.name,
        "userName": args.userName,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedDatabaseUserRole.
 */
export interface GetManagedDatabaseUserRoleOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire name.
     */
    name?: pulumi.Input<string>;
    /**
     * The name of the user whose details are to be viewed.
     */
    userName: pulumi.Input<string>;
}
