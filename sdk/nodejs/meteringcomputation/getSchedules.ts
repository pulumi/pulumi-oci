// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Schedules in Oracle Cloud Infrastructure Metering Computation service.
 *
 * Returns the saved schedule list.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSchedules = oci.MeteringComputation.getSchedules({
 *     compartmentId: compartmentId,
 *     name: scheduleName,
 * });
 * ```
 */
export function getSchedules(args: GetSchedulesArgs, opts?: pulumi.InvokeOptions): Promise<GetSchedulesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:MeteringComputation/getSchedules:getSchedules", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "name": args.name,
    }, opts);
}

/**
 * A collection of arguments for invoking getSchedules.
 */
export interface GetSchedulesArgs {
    /**
     * The compartment ID in which to list resources.
     */
    compartmentId: string;
    /**
     * The filter object for query usage.
     */
    filters?: inputs.MeteringComputation.GetSchedulesFilter[];
    /**
     * The query parameter for filtering by name.
     */
    name?: string;
}

/**
 * A collection of values returned by getSchedules.
 */
export interface GetSchedulesResult {
    /**
     * The customer tenancy.
     */
    readonly compartmentId: string;
    /**
     * The filter object for query usage.
     */
    readonly filters?: outputs.MeteringComputation.GetSchedulesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The unique name of the schedule created by the user.
     */
    readonly name?: string;
    /**
     * The list of schedule_collection.
     */
    readonly scheduleCollections: outputs.MeteringComputation.GetSchedulesScheduleCollection[];
}
/**
 * This data source provides the list of Schedules in Oracle Cloud Infrastructure Metering Computation service.
 *
 * Returns the saved schedule list.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSchedules = oci.MeteringComputation.getSchedules({
 *     compartmentId: compartmentId,
 *     name: scheduleName,
 * });
 * ```
 */
export function getSchedulesOutput(args: GetSchedulesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetSchedulesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:MeteringComputation/getSchedules:getSchedules", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "name": args.name,
    }, opts);
}

/**
 * A collection of arguments for invoking getSchedules.
 */
export interface GetSchedulesOutputArgs {
    /**
     * The compartment ID in which to list resources.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The filter object for query usage.
     */
    filters?: pulumi.Input<pulumi.Input<inputs.MeteringComputation.GetSchedulesFilterArgs>[]>;
    /**
     * The query parameter for filtering by name.
     */
    name?: pulumi.Input<string>;
}
