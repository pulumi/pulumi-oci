// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Managed Database resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Gets the details for the Managed Database specified by managedDatabaseId.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedDatabase = oci.DatabaseManagement.getManagedDatabase({
 *     managedDatabaseId: oci_database_management_managed_database.test_managed_database.id,
 * });
 * ```
 */
export function getManagedDatabase(args: GetManagedDatabaseArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedDatabaseResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:DatabaseManagement/getManagedDatabase:getManagedDatabase", {
        "managedDatabaseId": args.managedDatabaseId,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedDatabase.
 */
export interface GetManagedDatabaseArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: string;
}

/**
 * A collection of values returned by getManagedDatabase.
 */
export interface GetManagedDatabaseResult {
    /**
     * The additional details specific to a type of database defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
     */
    readonly additionalDetails: {[key: string]: any};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
     */
    readonly compartmentId: string;
    /**
     * The status of the Oracle Database. Indicates whether the status of the database is UP, DOWN, or UNKNOWN at the current time.
     */
    readonly databaseStatus: string;
    /**
     * The subtype of the Oracle Database. Indicates whether the database is a Container Database, Pluggable Database, Non-container Database, Autonomous Database, or Autonomous Container Database.
     */
    readonly databaseSubType: string;
    /**
     * The type of Oracle Database installation.
     */
    readonly databaseType: string;
    /**
     * The infrastructure used to deploy the Oracle Database.
     */
    readonly deploymentType: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Indicates whether the Oracle Database is part of a cluster.
     */
    readonly isCluster: boolean;
    /**
     * A list of Managed Database Groups that the Managed Database belongs to.
     */
    readonly managedDatabaseGroups: outputs.DatabaseManagement.GetManagedDatabaseManagedDatabaseGroup[];
    readonly managedDatabaseId: string;
    /**
     * The management option used when enabling Database Management.
     */
    readonly managementOption: string;
    /**
     * The name of the Managed Database.
     */
    readonly name: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the parent Container Database if Managed Database is a Pluggable Database.
     */
    readonly parentContainerId: string;
    /**
     * The date and time the Managed Database was created.
     */
    readonly timeCreated: string;
    /**
     * The workload type of the Autonomous Database.
     */
    readonly workloadType: string;
}

export function getManagedDatabaseOutput(args: GetManagedDatabaseOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetManagedDatabaseResult> {
    return pulumi.output(args).apply(a => getManagedDatabase(a, opts))
}

/**
 * A collection of arguments for invoking getManagedDatabase.
 */
export interface GetManagedDatabaseOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: pulumi.Input<string>;
}