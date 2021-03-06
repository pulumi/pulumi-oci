// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
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
 *     managedDatabaseId: oci_database_management_managed_database.test_managed_database.id,
 *     userName: oci_identity_user.test_user.name,
 *     name: _var.managed_database_user_role_name,
 * });
 * ```
 */
export function getManagedDatabaseUserRole(args: GetManagedDatabaseUserRoleArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedDatabaseUserRoleResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
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

export function getManagedDatabaseUserRoleOutput(args: GetManagedDatabaseUserRoleOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetManagedDatabaseUserRoleResult> {
    return pulumi.output(args).apply(a => getManagedDatabaseUserRole(a, opts))
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
