// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Namespace Storage Overlapping Recalls in Oracle Cloud Infrastructure Log Analytics service.
 *
 * This API gets the list of overlapping recalls made in the given timeframe
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNamespaceStorageOverlappingRecalls = oci.LogAnalytics.getNamespaceStorageOverlappingRecalls({
 *     namespace: _var.namespace_storage_overlapping_recall_namespace,
 *     timeDataEnded: _var.namespace_storage_overlapping_recall_time_data_ended,
 *     timeDataStarted: _var.namespace_storage_overlapping_recall_time_data_started,
 * });
 * ```
 */
export function getNamespaceStorageOverlappingRecalls(args: GetNamespaceStorageOverlappingRecallsArgs, opts?: pulumi.InvokeOptions): Promise<GetNamespaceStorageOverlappingRecallsResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:LogAnalytics/getNamespaceStorageOverlappingRecalls:getNamespaceStorageOverlappingRecalls", {
        "filters": args.filters,
        "namespace": args.namespace,
        "timeDataEnded": args.timeDataEnded,
        "timeDataStarted": args.timeDataStarted,
    }, opts);
}

/**
 * A collection of arguments for invoking getNamespaceStorageOverlappingRecalls.
 */
export interface GetNamespaceStorageOverlappingRecallsArgs {
    filters?: inputs.LogAnalytics.GetNamespaceStorageOverlappingRecallsFilter[];
    /**
     * The Logging Analytics namespace used for the request.
     */
    namespace: string;
    /**
     * This is the end of the time range for recalled data
     */
    timeDataEnded?: string;
    /**
     * This is the start of the time range for recalled data
     */
    timeDataStarted?: string;
}

/**
 * A collection of values returned by getNamespaceStorageOverlappingRecalls.
 */
export interface GetNamespaceStorageOverlappingRecallsResult {
    readonly filters?: outputs.LogAnalytics.GetNamespaceStorageOverlappingRecallsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly namespace: string;
    /**
     * The list of overlapping_recall_collection.
     */
    readonly overlappingRecallCollections: outputs.LogAnalytics.GetNamespaceStorageOverlappingRecallsOverlappingRecallCollection[];
    /**
     * This is the end of the time range of the archival data
     */
    readonly timeDataEnded?: string;
    /**
     * This is the start of the time range of the archival data
     */
    readonly timeDataStarted?: string;
}
/**
 * This data source provides the list of Namespace Storage Overlapping Recalls in Oracle Cloud Infrastructure Log Analytics service.
 *
 * This API gets the list of overlapping recalls made in the given timeframe
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNamespaceStorageOverlappingRecalls = oci.LogAnalytics.getNamespaceStorageOverlappingRecalls({
 *     namespace: _var.namespace_storage_overlapping_recall_namespace,
 *     timeDataEnded: _var.namespace_storage_overlapping_recall_time_data_ended,
 *     timeDataStarted: _var.namespace_storage_overlapping_recall_time_data_started,
 * });
 * ```
 */
export function getNamespaceStorageOverlappingRecallsOutput(args: GetNamespaceStorageOverlappingRecallsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetNamespaceStorageOverlappingRecallsResult> {
    return pulumi.output(args).apply((a: any) => getNamespaceStorageOverlappingRecalls(a, opts))
}

/**
 * A collection of arguments for invoking getNamespaceStorageOverlappingRecalls.
 */
export interface GetNamespaceStorageOverlappingRecallsOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.LogAnalytics.GetNamespaceStorageOverlappingRecallsFilterArgs>[]>;
    /**
     * The Logging Analytics namespace used for the request.
     */
    namespace: pulumi.Input<string>;
    /**
     * This is the end of the time range for recalled data
     */
    timeDataEnded?: pulumi.Input<string>;
    /**
     * This is the start of the time range for recalled data
     */
    timeDataStarted?: pulumi.Input<string>;
}