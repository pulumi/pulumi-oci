// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Awr Hub Awr Snapshot resource in Oracle Cloud Infrastructure Opsi service.
 *
 * Lists AWR snapshots for the specified source database in the AWR hub. The difference between the timeGreaterThanOrEqualTo and timeLessThanOrEqualTo should not exceed an elapsed range of 1 day.
 * The timeGreaterThanOrEqualTo & timeLessThanOrEqualTo params are optional. If these params are not provided, by default last 1 day snapshots will be returned.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAwrHubAwrSnapshot = oci.Opsi.getAwrHubAwrSnapshot({
 *     awrHubId: oci_opsi_awr_hub.test_awr_hub.id,
 *     awrSourceDatabaseIdentifier: _var.awr_hub_awr_snapshot_awr_source_database_identifier,
 *     timeGreaterThanOrEqualTo: _var.awr_hub_awr_snapshot_time_greater_than_or_equal_to,
 *     timeLessThanOrEqualTo: _var.awr_hub_awr_snapshot_time_less_than_or_equal_to,
 * });
 * ```
 */
export function getAwrHubAwrSnapshot(args: GetAwrHubAwrSnapshotArgs, opts?: pulumi.InvokeOptions): Promise<GetAwrHubAwrSnapshotResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Opsi/getAwrHubAwrSnapshot:getAwrHubAwrSnapshot", {
        "awrHubId": args.awrHubId,
        "awrSourceDatabaseIdentifier": args.awrSourceDatabaseIdentifier,
        "timeGreaterThanOrEqualTo": args.timeGreaterThanOrEqualTo,
        "timeLessThanOrEqualTo": args.timeLessThanOrEqualTo,
    }, opts);
}

/**
 * A collection of arguments for invoking getAwrHubAwrSnapshot.
 */
export interface GetAwrHubAwrSnapshotArgs {
    /**
     * Unique Awr Hub identifier
     */
    awrHubId: string;
    /**
     * AWR source database identifier.
     */
    awrSourceDatabaseIdentifier: string;
    /**
     * The optional greater than or equal to query parameter to filter the timestamp. The timestamp format to be followed is: YYYY-MM-DDTHH:MM:SSZ, example 2020-12-03T19:00:53Z
     */
    timeGreaterThanOrEqualTo?: string;
    /**
     * The optional less than or equal to query parameter to filter the timestamp. The timestamp format to be followed is: YYYY-MM-DDTHH:MM:SSZ, example 2020-12-03T19:00:53Z
     */
    timeLessThanOrEqualTo?: string;
}

/**
 * A collection of values returned by getAwrHubAwrSnapshot.
 */
export interface GetAwrHubAwrSnapshotResult {
    readonly awrHubId: string;
    readonly awrSourceDatabaseIdentifier: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * A list of AWR snapshot summary data.
     */
    readonly items: outputs.Opsi.GetAwrHubAwrSnapshotItem[];
    readonly timeGreaterThanOrEqualTo?: string;
    readonly timeLessThanOrEqualTo?: string;
}

export function getAwrHubAwrSnapshotOutput(args: GetAwrHubAwrSnapshotOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetAwrHubAwrSnapshotResult> {
    return pulumi.output(args).apply(a => getAwrHubAwrSnapshot(a, opts))
}

/**
 * A collection of arguments for invoking getAwrHubAwrSnapshot.
 */
export interface GetAwrHubAwrSnapshotOutputArgs {
    /**
     * Unique Awr Hub identifier
     */
    awrHubId: pulumi.Input<string>;
    /**
     * AWR source database identifier.
     */
    awrSourceDatabaseIdentifier: pulumi.Input<string>;
    /**
     * The optional greater than or equal to query parameter to filter the timestamp. The timestamp format to be followed is: YYYY-MM-DDTHH:MM:SSZ, example 2020-12-03T19:00:53Z
     */
    timeGreaterThanOrEqualTo?: pulumi.Input<string>;
    /**
     * The optional less than or equal to query parameter to filter the timestamp. The timestamp format to be followed is: YYYY-MM-DDTHH:MM:SSZ, example 2020-12-03T19:00:53Z
     */
    timeLessThanOrEqualTo?: pulumi.Input<string>;
}