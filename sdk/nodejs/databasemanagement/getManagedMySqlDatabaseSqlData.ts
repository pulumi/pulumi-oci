// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Managed My Sql Database Sql Data in Oracle Cloud Infrastructure Database Management service.
 *
 * Retrieves SQL performance data for given MySQL Instance.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedMySqlDatabaseSqlData = oci.DatabaseManagement.getManagedMySqlDatabaseSqlData({
 *     endTime: _var.managed_my_sql_database_sql_data_end_time,
 *     managedMySqlDatabaseId: oci_database_management_managed_my_sql_database.test_managed_my_sql_database.id,
 *     startTime: _var.managed_my_sql_database_sql_data_start_time,
 *     filterColumn: _var.managed_my_sql_database_sql_data_filter_column,
 * });
 * ```
 */
export function getManagedMySqlDatabaseSqlData(args: GetManagedMySqlDatabaseSqlDataArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedMySqlDatabaseSqlDataResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DatabaseManagement/getManagedMySqlDatabaseSqlData:getManagedMySqlDatabaseSqlData", {
        "endTime": args.endTime,
        "filterColumn": args.filterColumn,
        "filters": args.filters,
        "managedMySqlDatabaseId": args.managedMySqlDatabaseId,
        "startTime": args.startTime,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedMySqlDatabaseSqlData.
 */
export interface GetManagedMySqlDatabaseSqlDataArgs {
    /**
     * The end time of the time range to retrieve the health metrics of a Managed Database in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
     */
    endTime: string;
    /**
     * The parameter to filter results by key criteria.
     */
    filterColumn?: string;
    filters?: inputs.DatabaseManagement.GetManagedMySqlDatabaseSqlDataFilter[];
    /**
     * The OCID of ManagedMySqlDatabase.
     */
    managedMySqlDatabaseId: string;
    /**
     * The start time of the time range to retrieve the health metrics of a Managed Database in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
     */
    startTime: string;
}

/**
 * A collection of values returned by getManagedMySqlDatabaseSqlData.
 */
export interface GetManagedMySqlDatabaseSqlDataResult {
    readonly endTime: string;
    readonly filterColumn?: string;
    readonly filters?: outputs.DatabaseManagement.GetManagedMySqlDatabaseSqlDataFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly managedMySqlDatabaseId: string;
    /**
     * The list of my_sql_data_collection.
     */
    readonly mySqlDataCollections: outputs.DatabaseManagement.GetManagedMySqlDatabaseSqlDataMySqlDataCollection[];
    readonly startTime: string;
}
/**
 * This data source provides the list of Managed My Sql Database Sql Data in Oracle Cloud Infrastructure Database Management service.
 *
 * Retrieves SQL performance data for given MySQL Instance.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedMySqlDatabaseSqlData = oci.DatabaseManagement.getManagedMySqlDatabaseSqlData({
 *     endTime: _var.managed_my_sql_database_sql_data_end_time,
 *     managedMySqlDatabaseId: oci_database_management_managed_my_sql_database.test_managed_my_sql_database.id,
 *     startTime: _var.managed_my_sql_database_sql_data_start_time,
 *     filterColumn: _var.managed_my_sql_database_sql_data_filter_column,
 * });
 * ```
 */
export function getManagedMySqlDatabaseSqlDataOutput(args: GetManagedMySqlDatabaseSqlDataOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetManagedMySqlDatabaseSqlDataResult> {
    return pulumi.output(args).apply((a: any) => getManagedMySqlDatabaseSqlData(a, opts))
}

/**
 * A collection of arguments for invoking getManagedMySqlDatabaseSqlData.
 */
export interface GetManagedMySqlDatabaseSqlDataOutputArgs {
    /**
     * The end time of the time range to retrieve the health metrics of a Managed Database in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
     */
    endTime: pulumi.Input<string>;
    /**
     * The parameter to filter results by key criteria.
     */
    filterColumn?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.DatabaseManagement.GetManagedMySqlDatabaseSqlDataFilterArgs>[]>;
    /**
     * The OCID of ManagedMySqlDatabase.
     */
    managedMySqlDatabaseId: pulumi.Input<string>;
    /**
     * The start time of the time range to retrieve the health metrics of a Managed Database in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
     */
    startTime: pulumi.Input<string>;
}