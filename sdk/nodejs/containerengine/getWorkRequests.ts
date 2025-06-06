// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Work Requests in Oracle Cloud Infrastructure Container Engine service.
 *
 * List all work requests in a compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testWorkRequests = oci.ContainerEngine.getWorkRequests({
 *     compartmentId: compartmentId,
 *     clusterId: testCluster.id,
 *     resourceId: testResource.id,
 *     resourceType: workRequestResourceType,
 *     statuses: workRequestStatus,
 * });
 * ```
 */
export function getWorkRequests(args: GetWorkRequestsArgs, opts?: pulumi.InvokeOptions): Promise<GetWorkRequestsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:ContainerEngine/getWorkRequests:getWorkRequests", {
        "clusterId": args.clusterId,
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "resourceId": args.resourceId,
        "resourceType": args.resourceType,
        "statuses": args.statuses,
    }, opts);
}

/**
 * A collection of arguments for invoking getWorkRequests.
 */
export interface GetWorkRequestsArgs {
    /**
     * The OCID of the cluster.
     */
    clusterId?: string;
    /**
     * The OCID of the compartment.
     */
    compartmentId: string;
    filters?: inputs.ContainerEngine.GetWorkRequestsFilter[];
    /**
     * The OCID of the resource associated with a work request
     */
    resourceId?: string;
    /**
     * Type of the resource associated with a work request
     */
    resourceType?: string;
    /**
     * A work request status to filter on. Can have multiple parameters of this name.
     */
    statuses?: string[];
}

/**
 * A collection of values returned by getWorkRequests.
 */
export interface GetWorkRequestsResult {
    readonly clusterId?: string;
    /**
     * The OCID of the compartment in which the work request exists.
     */
    readonly compartmentId: string;
    readonly filters?: outputs.ContainerEngine.GetWorkRequestsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly resourceId?: string;
    readonly resourceType?: string;
    /**
     * The current status of the work request.
     */
    readonly statuses?: string[];
    /**
     * The list of work_requests.
     */
    readonly workRequests: outputs.ContainerEngine.GetWorkRequestsWorkRequest[];
}
/**
 * This data source provides the list of Work Requests in Oracle Cloud Infrastructure Container Engine service.
 *
 * List all work requests in a compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testWorkRequests = oci.ContainerEngine.getWorkRequests({
 *     compartmentId: compartmentId,
 *     clusterId: testCluster.id,
 *     resourceId: testResource.id,
 *     resourceType: workRequestResourceType,
 *     statuses: workRequestStatus,
 * });
 * ```
 */
export function getWorkRequestsOutput(args: GetWorkRequestsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetWorkRequestsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:ContainerEngine/getWorkRequests:getWorkRequests", {
        "clusterId": args.clusterId,
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "resourceId": args.resourceId,
        "resourceType": args.resourceType,
        "statuses": args.statuses,
    }, opts);
}

/**
 * A collection of arguments for invoking getWorkRequests.
 */
export interface GetWorkRequestsOutputArgs {
    /**
     * The OCID of the cluster.
     */
    clusterId?: pulumi.Input<string>;
    /**
     * The OCID of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.ContainerEngine.GetWorkRequestsFilterArgs>[]>;
    /**
     * The OCID of the resource associated with a work request
     */
    resourceId?: pulumi.Input<string>;
    /**
     * Type of the resource associated with a work request
     */
    resourceType?: pulumi.Input<string>;
    /**
     * A work request status to filter on. Can have multiple parameters of this name.
     */
    statuses?: pulumi.Input<pulumi.Input<string>[]>;
}
