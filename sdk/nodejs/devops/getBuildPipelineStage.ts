// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Build Pipeline Stage resource in Oracle Cloud Infrastructure Devops service.
 *
 * Retrieves a stage based on the stage ID provided in the request.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBuildPipelineStage = oci.DevOps.getBuildPipelineStage({
 *     buildPipelineStageId: oci_devops_build_pipeline_stage.test_build_pipeline_stage.id,
 * });
 * ```
 */
export function getBuildPipelineStage(args: GetBuildPipelineStageArgs, opts?: pulumi.InvokeOptions): Promise<GetBuildPipelineStageResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:DevOps/getBuildPipelineStage:getBuildPipelineStage", {
        "buildPipelineStageId": args.buildPipelineStageId,
    }, opts);
}

/**
 * A collection of arguments for invoking getBuildPipelineStage.
 */
export interface GetBuildPipelineStageArgs {
    /**
     * Unique stage identifier.
     */
    buildPipelineStageId: string;
}

/**
 * A collection of values returned by getBuildPipelineStage.
 */
export interface GetBuildPipelineStageResult {
    /**
     * The OCID of the build pipeline.
     */
    readonly buildPipelineId: string;
    readonly buildPipelineStageId: string;
    /**
     * The collection containing the predecessors of a stage.
     */
    readonly buildPipelineStagePredecessorCollections: outputs.DevOps.GetBuildPipelineStageBuildPipelineStagePredecessorCollection[];
    /**
     * Defines the stage type, which is one of the following: BUILD, DELIVER_ARTIFACT, WAIT, and TRIGGER_DEPLOYMENT_PIPELINE.
     */
    readonly buildPipelineStageType: string;
    /**
     * Collection of build sources.
     */
    readonly buildSourceCollections: outputs.DevOps.GetBuildPipelineStageBuildSourceCollection[];
    /**
     * The path to the build specification file for this environment. The default location of the file if not specified is build_spec.yaml.
     */
    readonly buildSpecFile: string;
    /**
     * The OCID of the compartment where the pipeline is created.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * Specifies an array of artifacts that need to be pushed to the artifactory stores.
     */
    readonly deliverArtifactCollections: outputs.DevOps.GetBuildPipelineStageDeliverArtifactCollection[];
    /**
     * A target deployment pipeline OCID that will run in this stage.
     */
    readonly deployPipelineId: string;
    /**
     * Optional description about the build stage.
     */
    readonly description: string;
    /**
     * Stage display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * Unique identifier that is immutable on creation.
     */
    readonly id: string;
    /**
     * Image name for the build environment.
     */
    readonly image: string;
    /**
     * A boolean flag that specifies whether all the parameters must be passed when the deployment is triggered.
     */
    readonly isPassAllParametersEnabled: boolean;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    readonly lifecycleDetails: string;
    /**
     * Name of the build source where the build_spec.yml file is located. If not specified, then the first entry in the build source collection is chosen as primary build source.
     */
    readonly primaryBuildSource: string;
    /**
     * Specifies the configuration needed when the target Oracle Cloud Infrastructure resource, i.e., OKE cluster, resides in customer's private network.
     */
    readonly privateAccessConfigs: outputs.DevOps.GetBuildPipelineStagePrivateAccessConfig[];
    /**
     * The OCID of the DevOps project.
     */
    readonly projectId: string;
    /**
     * Timeout for the build stage execution. Specify value in seconds.
     */
    readonly stageExecutionTimeoutInSeconds: number;
    /**
     * The current state of the stage.
     */
    readonly state: string;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * The time the stage was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     */
    readonly timeCreated: string;
    /**
     * The time the stage was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     */
    readonly timeUpdated: string;
    /**
     * Specifies wait criteria for the Wait stage.
     */
    readonly waitCriterias: outputs.DevOps.GetBuildPipelineStageWaitCriteria[];
}

export function getBuildPipelineStageOutput(args: GetBuildPipelineStageOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetBuildPipelineStageResult> {
    return pulumi.output(args).apply(a => getBuildPipelineStage(a, opts))
}

/**
 * A collection of arguments for invoking getBuildPipelineStage.
 */
export interface GetBuildPipelineStageOutputArgs {
    /**
     * Unique stage identifier.
     */
    buildPipelineStageId: pulumi.Input<string>;
}