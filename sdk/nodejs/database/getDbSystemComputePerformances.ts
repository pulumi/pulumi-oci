// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Db System Compute Performances in Oracle Cloud Infrastructure Database service.
 *
 * Gets a list of expected compute performance parameters for a virtual machine DB system based on system configuration.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDbSystemComputePerformances = oci.Database.getDbSystemComputePerformances({
 *     dbSystemShape: dbSystemComputePerformanceDbSystemShape,
 * });
 * ```
 */
export function getDbSystemComputePerformances(args?: GetDbSystemComputePerformancesArgs, opts?: pulumi.InvokeOptions): Promise<GetDbSystemComputePerformancesResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Database/getDbSystemComputePerformances:getDbSystemComputePerformances", {
        "dbSystemShape": args.dbSystemShape,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getDbSystemComputePerformances.
 */
export interface GetDbSystemComputePerformancesArgs {
    /**
     * If provided, filters the results to the set of database versions which are supported for the given shape.
     */
    dbSystemShape?: string;
    filters?: inputs.Database.GetDbSystemComputePerformancesFilter[];
}

/**
 * A collection of values returned by getDbSystemComputePerformances.
 */
export interface GetDbSystemComputePerformancesResult {
    /**
     * The list of db_system_compute_performances.
     */
    readonly dbSystemComputePerformances: outputs.Database.GetDbSystemComputePerformancesDbSystemComputePerformance[];
    readonly dbSystemShape?: string;
    readonly filters?: outputs.Database.GetDbSystemComputePerformancesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
}
/**
 * This data source provides the list of Db System Compute Performances in Oracle Cloud Infrastructure Database service.
 *
 * Gets a list of expected compute performance parameters for a virtual machine DB system based on system configuration.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDbSystemComputePerformances = oci.Database.getDbSystemComputePerformances({
 *     dbSystemShape: dbSystemComputePerformanceDbSystemShape,
 * });
 * ```
 */
export function getDbSystemComputePerformancesOutput(args?: GetDbSystemComputePerformancesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDbSystemComputePerformancesResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Database/getDbSystemComputePerformances:getDbSystemComputePerformances", {
        "dbSystemShape": args.dbSystemShape,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getDbSystemComputePerformances.
 */
export interface GetDbSystemComputePerformancesOutputArgs {
    /**
     * If provided, filters the results to the set of database versions which are supported for the given shape.
     */
    dbSystemShape?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Database.GetDbSystemComputePerformancesFilterArgs>[]>;
}
