// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Detect Anomaly Jobs in Oracle Cloud Infrastructure Ai Anomaly Detection service.
 *
 * Returns a list of all the Anomaly Detection jobs in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDetectAnomalyJobs = oci.AiAnomalyDetection.getDetectAnomalyJobs({
 *     compartmentId: compartmentId,
 *     detectAnomalyJobId: testDetectAnomalyJob.id,
 *     displayName: detectAnomalyJobDisplayName,
 *     modelId: testModel.id,
 *     projectId: testProject.id,
 *     state: detectAnomalyJobState,
 * });
 * ```
 */
export function getDetectAnomalyJobs(args: GetDetectAnomalyJobsArgs, opts?: pulumi.InvokeOptions): Promise<GetDetectAnomalyJobsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:AiAnomalyDetection/getDetectAnomalyJobs:getDetectAnomalyJobs", {
        "compartmentId": args.compartmentId,
        "detectAnomalyJobId": args.detectAnomalyJobId,
        "displayName": args.displayName,
        "filters": args.filters,
        "modelId": args.modelId,
        "projectId": args.projectId,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getDetectAnomalyJobs.
 */
export interface GetDetectAnomalyJobsArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * Unique Async Job identifier
     */
    detectAnomalyJobId?: string;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: string;
    filters?: inputs.AiAnomalyDetection.GetDetectAnomalyJobsFilter[];
    /**
     * The ID of the trained model for which to list the resources.
     */
    modelId?: string;
    /**
     * The ID of the project for which to list the objects.
     */
    projectId?: string;
    /**
     * <b>Filter</b> results by the specified lifecycle state. Must be a valid state for the resource type.
     */
    state?: string;
}

/**
 * A collection of values returned by getDetectAnomalyJobs.
 */
export interface GetDetectAnomalyJobsResult {
    /**
     * The OCID of the compartment that starts the job.
     */
    readonly compartmentId: string;
    /**
     * The list of detect_anomaly_job_collection.
     */
    readonly detectAnomalyJobCollections: outputs.AiAnomalyDetection.GetDetectAnomalyJobsDetectAnomalyJobCollection[];
    readonly detectAnomalyJobId?: string;
    /**
     * Detect anomaly job display name.
     */
    readonly displayName?: string;
    readonly filters?: outputs.AiAnomalyDetection.GetDetectAnomalyJobsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The OCID of the trained model.
     */
    readonly modelId?: string;
    /**
     * The OCID of the project.
     */
    readonly projectId?: string;
    /**
     * The current state of the batch document job.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Detect Anomaly Jobs in Oracle Cloud Infrastructure Ai Anomaly Detection service.
 *
 * Returns a list of all the Anomaly Detection jobs in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDetectAnomalyJobs = oci.AiAnomalyDetection.getDetectAnomalyJobs({
 *     compartmentId: compartmentId,
 *     detectAnomalyJobId: testDetectAnomalyJob.id,
 *     displayName: detectAnomalyJobDisplayName,
 *     modelId: testModel.id,
 *     projectId: testProject.id,
 *     state: detectAnomalyJobState,
 * });
 * ```
 */
export function getDetectAnomalyJobsOutput(args: GetDetectAnomalyJobsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDetectAnomalyJobsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:AiAnomalyDetection/getDetectAnomalyJobs:getDetectAnomalyJobs", {
        "compartmentId": args.compartmentId,
        "detectAnomalyJobId": args.detectAnomalyJobId,
        "displayName": args.displayName,
        "filters": args.filters,
        "modelId": args.modelId,
        "projectId": args.projectId,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getDetectAnomalyJobs.
 */
export interface GetDetectAnomalyJobsOutputArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * Unique Async Job identifier
     */
    detectAnomalyJobId?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.AiAnomalyDetection.GetDetectAnomalyJobsFilterArgs>[]>;
    /**
     * The ID of the trained model for which to list the resources.
     */
    modelId?: pulumi.Input<string>;
    /**
     * The ID of the project for which to list the objects.
     */
    projectId?: pulumi.Input<string>;
    /**
     * <b>Filter</b> results by the specified lifecycle state. Must be a valid state for the resource type.
     */
    state?: pulumi.Input<string>;
}
