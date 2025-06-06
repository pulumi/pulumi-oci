// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Build Pipeline Stages in Oracle Cloud Infrastructure Devops service.
 *
 * Returns a list of all stages in a compartment or build pipeline.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBuildPipelineStages = oci.DevOps.getBuildPipelineStages({
 *     buildPipelineId: testBuildPipeline.id,
 *     compartmentId: compartmentId,
 *     displayName: buildPipelineStageDisplayName,
 *     id: buildPipelineStageId,
 *     state: buildPipelineStageState,
 * });
 * ```
 */
export function getBuildPipelineStages(args?: GetBuildPipelineStagesArgs, opts?: pulumi.InvokeOptions): Promise<GetBuildPipelineStagesResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DevOps/getBuildPipelineStages:getBuildPipelineStages", {
        "buildPipelineId": args.buildPipelineId,
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "id": args.id,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getBuildPipelineStages.
 */
export interface GetBuildPipelineStagesArgs {
    /**
     * The OCID of the parent build pipeline.
     */
    buildPipelineId?: string;
    /**
     * The OCID of the compartment in which to list resources.
     */
    compartmentId?: string;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: string;
    filters?: inputs.DevOps.GetBuildPipelineStagesFilter[];
    /**
     * Unique identifier or OCID for listing a single resource by ID.
     */
    id?: string;
    /**
     * A filter to return the stages that matches the given lifecycle state.
     */
    state?: string;
}

/**
 * A collection of values returned by getBuildPipelineStages.
 */
export interface GetBuildPipelineStagesResult {
    /**
     * The OCID of the build pipeline.
     */
    readonly buildPipelineId?: string;
    /**
     * The list of build_pipeline_stage_collection.
     */
    readonly buildPipelineStageCollections: outputs.DevOps.GetBuildPipelineStagesBuildPipelineStageCollection[];
    /**
     * The OCID of the compartment where the pipeline is created.
     */
    readonly compartmentId?: string;
    /**
     * Stage display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly filters?: outputs.DevOps.GetBuildPipelineStagesFilter[];
    /**
     * Unique identifier that is immutable on creation.
     */
    readonly id?: string;
    /**
     * The current state of the stage.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Build Pipeline Stages in Oracle Cloud Infrastructure Devops service.
 *
 * Returns a list of all stages in a compartment or build pipeline.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBuildPipelineStages = oci.DevOps.getBuildPipelineStages({
 *     buildPipelineId: testBuildPipeline.id,
 *     compartmentId: compartmentId,
 *     displayName: buildPipelineStageDisplayName,
 *     id: buildPipelineStageId,
 *     state: buildPipelineStageState,
 * });
 * ```
 */
export function getBuildPipelineStagesOutput(args?: GetBuildPipelineStagesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetBuildPipelineStagesResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DevOps/getBuildPipelineStages:getBuildPipelineStages", {
        "buildPipelineId": args.buildPipelineId,
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "id": args.id,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getBuildPipelineStages.
 */
export interface GetBuildPipelineStagesOutputArgs {
    /**
     * The OCID of the parent build pipeline.
     */
    buildPipelineId?: pulumi.Input<string>;
    /**
     * The OCID of the compartment in which to list resources.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.DevOps.GetBuildPipelineStagesFilterArgs>[]>;
    /**
     * Unique identifier or OCID for listing a single resource by ID.
     */
    id?: pulumi.Input<string>;
    /**
     * A filter to return the stages that matches the given lifecycle state.
     */
    state?: pulumi.Input<string>;
}
