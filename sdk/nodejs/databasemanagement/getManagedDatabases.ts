// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Managed Databases in Oracle Cloud Infrastructure Database Management service.
 *
 * Gets the Managed Database for a specific ID or the list of Managed Databases in a specific compartment.
 * Managed Databases can be filtered based on the name parameter. Only one of the parameters, ID or name
 * should be provided. If neither of these parameters is provided, all the Managed Databases in the compartment
 * are listed. Managed Databases can also be filtered based on the deployment type and management option.
 * If the deployment type is not specified or if it is `ONPREMISE`, then the management option is not
 * considered and Managed Databases with `ADVANCED` management option are listed.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedDatabases = oci.DatabaseManagement.getManagedDatabases({
 *     compartmentId: _var.compartment_id,
 *     deploymentType: _var.managed_database_deployment_type,
 *     id: _var.managed_database_id,
 *     managementOption: _var.managed_database_management_option,
 *     name: _var.managed_database_name,
 * });
 * ```
 */
export function getManagedDatabases(args: GetManagedDatabasesArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedDatabasesResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:DatabaseManagement/getManagedDatabases:getManagedDatabases", {
        "compartmentId": args.compartmentId,
        "deploymentType": args.deploymentType,
        "filters": args.filters,
        "id": args.id,
        "managementOption": args.managementOption,
        "name": args.name,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedDatabases.
 */
export interface GetManagedDatabasesArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * A filter to return Managed Databases of the specified deployment type.
     */
    deploymentType?: string;
    filters?: inputs.DatabaseManagement.GetManagedDatabasesFilter[];
    /**
     * The identifier of the resource.
     */
    id?: string;
    /**
     * A filter to return Managed Databases with the specified management option.
     */
    managementOption?: string;
    /**
     * A filter to return only resources that match the entire name.
     */
    name?: string;
}

/**
 * A collection of values returned by getManagedDatabases.
 */
export interface GetManagedDatabasesResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
     */
    readonly compartmentId: string;
    /**
     * The infrastructure used to deploy the Oracle Database.
     */
    readonly deploymentType?: string;
    readonly filters?: outputs.DatabaseManagement.GetManagedDatabasesFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database Group.
     */
    readonly id?: string;
    /**
     * The list of managed_database_collection.
     */
    readonly managedDatabaseCollections: outputs.DatabaseManagement.GetManagedDatabasesManagedDatabaseCollection[];
    /**
     * The management option used when enabling Database Management.
     */
    readonly managementOption?: string;
    /**
     * The name of the Managed Database.
     */
    readonly name?: string;
}

export function getManagedDatabasesOutput(args: GetManagedDatabasesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetManagedDatabasesResult> {
    return pulumi.output(args).apply(a => getManagedDatabases(a, opts))
}

/**
 * A collection of arguments for invoking getManagedDatabases.
 */
export interface GetManagedDatabasesOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return Managed Databases of the specified deployment type.
     */
    deploymentType?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.DatabaseManagement.GetManagedDatabasesFilterArgs>[]>;
    /**
     * The identifier of the resource.
     */
    id?: pulumi.Input<string>;
    /**
     * A filter to return Managed Databases with the specified management option.
     */
    managementOption?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire name.
     */
    name?: pulumi.Input<string>;
}