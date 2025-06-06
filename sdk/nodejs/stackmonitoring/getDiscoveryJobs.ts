// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Discovery Jobs in Oracle Cloud Infrastructure Stack Monitoring service.
 *
 * API to get the details of all Discovery Jobs.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDiscoveryJobs = oci.StackMonitoring.getDiscoveryJobs({
 *     compartmentId: compartmentId,
 *     name: discoveryJobName,
 * });
 * ```
 */
export function getDiscoveryJobs(args: GetDiscoveryJobsArgs, opts?: pulumi.InvokeOptions): Promise<GetDiscoveryJobsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:StackMonitoring/getDiscoveryJobs:getDiscoveryJobs", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "name": args.name,
    }, opts);
}

/**
 * A collection of arguments for invoking getDiscoveryJobs.
 */
export interface GetDiscoveryJobsArgs {
    /**
     * The ID of the compartment in which data is listed.
     */
    compartmentId: string;
    filters?: inputs.StackMonitoring.GetDiscoveryJobsFilter[];
    /**
     * A filter to return only discovery jobs that match the entire resource name given.
     */
    name?: string;
}

/**
 * A collection of values returned by getDiscoveryJobs.
 */
export interface GetDiscoveryJobsResult {
    /**
     * The OCID of the Compartment
     */
    readonly compartmentId: string;
    /**
     * The list of discovery_job_collection.
     */
    readonly discoveryJobCollections: outputs.StackMonitoring.GetDiscoveryJobsDiscoveryJobCollection[];
    readonly filters?: outputs.StackMonitoring.GetDiscoveryJobsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly name?: string;
}
/**
 * This data source provides the list of Discovery Jobs in Oracle Cloud Infrastructure Stack Monitoring service.
 *
 * API to get the details of all Discovery Jobs.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDiscoveryJobs = oci.StackMonitoring.getDiscoveryJobs({
 *     compartmentId: compartmentId,
 *     name: discoveryJobName,
 * });
 * ```
 */
export function getDiscoveryJobsOutput(args: GetDiscoveryJobsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDiscoveryJobsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:StackMonitoring/getDiscoveryJobs:getDiscoveryJobs", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "name": args.name,
    }, opts);
}

/**
 * A collection of arguments for invoking getDiscoveryJobs.
 */
export interface GetDiscoveryJobsOutputArgs {
    /**
     * The ID of the compartment in which data is listed.
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.StackMonitoring.GetDiscoveryJobsFilterArgs>[]>;
    /**
     * A filter to return only discovery jobs that match the entire resource name given.
     */
    name?: pulumi.Input<string>;
}
