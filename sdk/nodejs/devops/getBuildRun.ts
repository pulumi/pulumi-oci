// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Build Run resource in Oracle Cloud Infrastructure Devops service.
 *
 * Returns the details of a build run for a given build run ID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBuildRun = oci.DevOps.getBuildRun({
 *     buildRunId: testBuildRunOciDevopsBuildRun.id,
 * });
 * ```
 */
export function getBuildRun(args: GetBuildRunArgs, opts?: pulumi.InvokeOptions): Promise<GetBuildRunResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DevOps/getBuildRun:getBuildRun", {
        "buildRunId": args.buildRunId,
    }, opts);
}

/**
 * A collection of arguments for invoking getBuildRun.
 */
export interface GetBuildRunArgs {
    /**
     * Unique build run identifier.
     */
    buildRunId: string;
}

/**
 * A collection of values returned by getBuildRun.
 */
export interface GetBuildRunResult {
    /**
     * Outputs from the build.
     */
    readonly buildOutputs: outputs.DevOps.GetBuildRunBuildOutput[];
    /**
     * The OCID of the build pipeline to be triggered.
     */
    readonly buildPipelineId: string;
    /**
     * Specifies list of arguments passed along with the build run.
     */
    readonly buildRunArguments: outputs.DevOps.GetBuildRunBuildRunArgument[];
    readonly buildRunId: string;
    /**
     * The run progress details of a build run.
     */
    readonly buildRunProgresses: outputs.DevOps.GetBuildRunBuildRunProgress[];
    /**
     * The source from which the build run is triggered.
     */
    readonly buildRunSources: outputs.DevOps.GetBuildRunBuildRunSource[];
    /**
     * Commit details that need to be used for the build run.
     */
    readonly commitInfos: outputs.DevOps.GetBuildRunCommitInfo[];
    /**
     * The OCID of the compartment where the build is running.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * Build run display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * Unique identifier that is immutable on creation.
     */
    readonly id: string;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    readonly lifecycleDetails: string;
    /**
     * The OCID of the DevOps project.
     */
    readonly projectId: string;
    /**
     * The current state of the build run.
     */
    readonly state: string;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The time the build run was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     */
    readonly timeCreated: string;
    /**
     * The time the build run was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Build Run resource in Oracle Cloud Infrastructure Devops service.
 *
 * Returns the details of a build run for a given build run ID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBuildRun = oci.DevOps.getBuildRun({
 *     buildRunId: testBuildRunOciDevopsBuildRun.id,
 * });
 * ```
 */
export function getBuildRunOutput(args: GetBuildRunOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetBuildRunResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DevOps/getBuildRun:getBuildRun", {
        "buildRunId": args.buildRunId,
    }, opts);
}

/**
 * A collection of arguments for invoking getBuildRun.
 */
export interface GetBuildRunOutputArgs {
    /**
     * Unique build run identifier.
     */
    buildRunId: pulumi.Input<string>;
}
