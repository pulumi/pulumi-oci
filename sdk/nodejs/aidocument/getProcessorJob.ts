// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Processor Job resource in Oracle Cloud Infrastructure Ai Document service.
 *
 * Get the details of a processor job.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testProcessorJob = oci.AiDocument.getProcessorJob({
 *     processorJobId: testProcessorJobOciAiDocumentProcessorJob.id,
 * });
 * ```
 */
export function getProcessorJob(args: GetProcessorJobArgs, opts?: pulumi.InvokeOptions): Promise<GetProcessorJobResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:AiDocument/getProcessorJob:getProcessorJob", {
        "processorJobId": args.processorJobId,
    }, opts);
}

/**
 * A collection of arguments for invoking getProcessorJob.
 */
export interface GetProcessorJobArgs {
    /**
     * Processor job id.
     */
    processorJobId: string;
}

/**
 * A collection of values returned by getProcessorJob.
 */
export interface GetProcessorJobResult {
    /**
     * The compartment identifier.
     */
    readonly compartmentId: string;
    /**
     * The display name of the processor job.
     */
    readonly displayName: string;
    /**
     * The id of the processor job.
     */
    readonly id: string;
    /**
     * The location of the inputs.
     */
    readonly inputLocations: outputs.AiDocument.GetProcessorJobInputLocation[];
    /**
     * The detailed status of FAILED state.
     */
    readonly lifecycleDetails: string;
    /**
     * The object storage location where to store analysis results.
     */
    readonly outputLocations: outputs.AiDocument.GetProcessorJobOutputLocation[];
    /**
     * How much progress the operation has made, compared to the total amount of work to be performed.
     */
    readonly percentComplete: number;
    /**
     * The configuration of a processor.
     */
    readonly processorConfigs: outputs.AiDocument.GetProcessorJobProcessorConfig[];
    readonly processorJobId: string;
    /**
     * The current state of the processor job.
     */
    readonly state: string;
    /**
     * The job acceptance time.
     */
    readonly timeAccepted: string;
    /**
     * The job finish time.
     */
    readonly timeFinished: string;
    /**
     * The job start time.
     */
    readonly timeStarted: string;
}
/**
 * This data source provides details about a specific Processor Job resource in Oracle Cloud Infrastructure Ai Document service.
 *
 * Get the details of a processor job.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testProcessorJob = oci.AiDocument.getProcessorJob({
 *     processorJobId: testProcessorJobOciAiDocumentProcessorJob.id,
 * });
 * ```
 */
export function getProcessorJobOutput(args: GetProcessorJobOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetProcessorJobResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:AiDocument/getProcessorJob:getProcessorJob", {
        "processorJobId": args.processorJobId,
    }, opts);
}

/**
 * A collection of arguments for invoking getProcessorJob.
 */
export interface GetProcessorJobOutputArgs {
    /**
     * Processor job id.
     */
    processorJobId: pulumi.Input<string>;
}
