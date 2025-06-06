// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Pipeline Running Processes in Oracle Cloud Infrastructure Golden Gate service.
 *
 * Retrieves a Pipeline's running replication process's status like Capture/Apply.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testPipelineRunningProcesses = oci.GoldenGate.getPipelineRunningProcesses({
 *     pipelineId: testPipeline.id,
 * });
 * ```
 */
export function getPipelineRunningProcesses(args: GetPipelineRunningProcessesArgs, opts?: pulumi.InvokeOptions): Promise<GetPipelineRunningProcessesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:GoldenGate/getPipelineRunningProcesses:getPipelineRunningProcesses", {
        "filters": args.filters,
        "pipelineId": args.pipelineId,
    }, opts);
}

/**
 * A collection of arguments for invoking getPipelineRunningProcesses.
 */
export interface GetPipelineRunningProcessesArgs {
    filters?: inputs.GoldenGate.GetPipelineRunningProcessesFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline created.
     */
    pipelineId: string;
}

/**
 * A collection of values returned by getPipelineRunningProcesses.
 */
export interface GetPipelineRunningProcessesResult {
    readonly filters?: outputs.GoldenGate.GetPipelineRunningProcessesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly pipelineId: string;
    /**
     * The list of pipeline_running_process_collection.
     */
    readonly pipelineRunningProcessCollections: outputs.GoldenGate.GetPipelineRunningProcessesPipelineRunningProcessCollection[];
}
/**
 * This data source provides the list of Pipeline Running Processes in Oracle Cloud Infrastructure Golden Gate service.
 *
 * Retrieves a Pipeline's running replication process's status like Capture/Apply.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testPipelineRunningProcesses = oci.GoldenGate.getPipelineRunningProcesses({
 *     pipelineId: testPipeline.id,
 * });
 * ```
 */
export function getPipelineRunningProcessesOutput(args: GetPipelineRunningProcessesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetPipelineRunningProcessesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:GoldenGate/getPipelineRunningProcesses:getPipelineRunningProcesses", {
        "filters": args.filters,
        "pipelineId": args.pipelineId,
    }, opts);
}

/**
 * A collection of arguments for invoking getPipelineRunningProcesses.
 */
export interface GetPipelineRunningProcessesOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.GoldenGate.GetPipelineRunningProcessesFilterArgs>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline created.
     */
    pipelineId: pulumi.Input<string>;
}
