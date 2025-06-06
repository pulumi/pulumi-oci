// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Managed Database Table Statistics in Oracle Cloud Infrastructure Database Management service.
 *
 * Gets the number of database table objects grouped by different statuses such as
 * Not Stale Stats, Stale Stats, and No Stats. This also includes the percentage of each status.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedDatabaseTableStatistics = oci.DatabaseManagement.getManagedDatabaseTableStatistics({
 *     managedDatabaseId: testManagedDatabase.id,
 * });
 * ```
 */
export function getManagedDatabaseTableStatistics(args: GetManagedDatabaseTableStatisticsArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedDatabaseTableStatisticsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DatabaseManagement/getManagedDatabaseTableStatistics:getManagedDatabaseTableStatistics", {
        "filters": args.filters,
        "managedDatabaseId": args.managedDatabaseId,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedDatabaseTableStatistics.
 */
export interface GetManagedDatabaseTableStatisticsArgs {
    filters?: inputs.DatabaseManagement.GetManagedDatabaseTableStatisticsFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: string;
}

/**
 * A collection of values returned by getManagedDatabaseTableStatistics.
 */
export interface GetManagedDatabaseTableStatisticsResult {
    readonly filters?: outputs.DatabaseManagement.GetManagedDatabaseTableStatisticsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly managedDatabaseId: string;
    /**
     * The list of table_statistics_collection.
     */
    readonly tableStatisticsCollections: outputs.DatabaseManagement.GetManagedDatabaseTableStatisticsTableStatisticsCollection[];
}
/**
 * This data source provides the list of Managed Database Table Statistics in Oracle Cloud Infrastructure Database Management service.
 *
 * Gets the number of database table objects grouped by different statuses such as
 * Not Stale Stats, Stale Stats, and No Stats. This also includes the percentage of each status.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedDatabaseTableStatistics = oci.DatabaseManagement.getManagedDatabaseTableStatistics({
 *     managedDatabaseId: testManagedDatabase.id,
 * });
 * ```
 */
export function getManagedDatabaseTableStatisticsOutput(args: GetManagedDatabaseTableStatisticsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetManagedDatabaseTableStatisticsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DatabaseManagement/getManagedDatabaseTableStatistics:getManagedDatabaseTableStatistics", {
        "filters": args.filters,
        "managedDatabaseId": args.managedDatabaseId,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedDatabaseTableStatistics.
 */
export interface GetManagedDatabaseTableStatisticsOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.DatabaseManagement.GetManagedDatabaseTableStatisticsFilterArgs>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: pulumi.Input<string>;
}
