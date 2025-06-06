// *** WARNING: this file was generated by pulumi-language-nodejs. ***
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
 *     endTime: managedMySqlDatabaseSqlDataEndTime,
 *     managedMySqlDatabaseId: testManagedMySqlDatabase.id,
 *     startTime: managedMySqlDatabaseSqlDataStartTime,
 *     filterColumn: managedMySqlDatabaseSqlDataFilterColumn,
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
     * The parameter to filter results by key criteria which include :
     * * AVG_TIMER_WAIT
     * * SUM_TIMER_WAIT
     * * COUNT_STAR
     * * SUM_ERRORS
     * * SUM_ROWS_AFFECTED
     * * SUM_ROWS_SENT
     * * SUM_ROWS_EXAMINED
     * * SUM_CREATED_TMP_TABLES
     * * SUM_NO_INDEX_USED
     * * SUM_NO_GOOD_INDEX_USED
     * * FIRST_SEEN
     * * LAST_SEEN
     * * HEATWAVE_OFFLOADED
     * * HEATWAVE_OUT_OF_MEMORY
     */
    filterColumn?: string;
    filters?: inputs.DatabaseManagement.GetManagedMySqlDatabaseSqlDataFilter[];
    /**
     * The OCID of the Managed MySQL Database.
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
 *     endTime: managedMySqlDatabaseSqlDataEndTime,
 *     managedMySqlDatabaseId: testManagedMySqlDatabase.id,
 *     startTime: managedMySqlDatabaseSqlDataStartTime,
 *     filterColumn: managedMySqlDatabaseSqlDataFilterColumn,
 * });
 * ```
 */
export function getManagedMySqlDatabaseSqlDataOutput(args: GetManagedMySqlDatabaseSqlDataOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetManagedMySqlDatabaseSqlDataResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DatabaseManagement/getManagedMySqlDatabaseSqlData:getManagedMySqlDatabaseSqlData", {
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
export interface GetManagedMySqlDatabaseSqlDataOutputArgs {
    /**
     * The end time of the time range to retrieve the health metrics of a Managed Database in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
     */
    endTime: pulumi.Input<string>;
    /**
     * The parameter to filter results by key criteria which include :
     * * AVG_TIMER_WAIT
     * * SUM_TIMER_WAIT
     * * COUNT_STAR
     * * SUM_ERRORS
     * * SUM_ROWS_AFFECTED
     * * SUM_ROWS_SENT
     * * SUM_ROWS_EXAMINED
     * * SUM_CREATED_TMP_TABLES
     * * SUM_NO_INDEX_USED
     * * SUM_NO_GOOD_INDEX_USED
     * * FIRST_SEEN
     * * LAST_SEEN
     * * HEATWAVE_OFFLOADED
     * * HEATWAVE_OUT_OF_MEMORY
     */
    filterColumn?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.DatabaseManagement.GetManagedMySqlDatabaseSqlDataFilterArgs>[]>;
    /**
     * The OCID of the Managed MySQL Database.
     */
    managedMySqlDatabaseId: pulumi.Input<string>;
    /**
     * The start time of the time range to retrieve the health metrics of a Managed Database in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
     */
    startTime: pulumi.Input<string>;
}
