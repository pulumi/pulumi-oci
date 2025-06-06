// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Project resource in Oracle Cloud Infrastructure Ai Document service.
 *
 * Get a project by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testProject = oci.AiDocument.getProject({
 *     projectId: testProjectOciAiDocumentProject.id,
 * });
 * ```
 */
export function getProject(args: GetProjectArgs, opts?: pulumi.InvokeOptions): Promise<GetProjectResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:AiDocument/getProject:getProject", {
        "projectId": args.projectId,
    }, opts);
}

/**
 * A collection of arguments for invoking getProject.
 */
export interface GetProjectArgs {
    /**
     * A unique project identifier.
     */
    projectId: string;
}

/**
 * A collection of values returned by getProject.
 */
export interface GetProjectResult {
    /**
     * The compartment identifier.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For example: `{"foo-namespace": {"bar-key": "value"}}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * An optional description of the project.
     */
    readonly description: string;
    /**
     * A human-friendly name for the project, which can be changed.
     */
    readonly displayName: string;
    /**
     * A simple key-value pair that is applied without any predefined name, type, or scope. It exists for cross-compatibility only. For example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * A unique identifier that is immutable after creation.
     */
    readonly id: string;
    /**
     * A message describing the current state in more detail, that can provide actionable information if creation failed.
     */
    readonly lifecycleDetails: string;
    readonly projectId: string;
    /**
     * The current state of the project.
     */
    readonly state: string;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. For example: `{"orcl-cloud": {"free-tier-retained": "true"}}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * When the project was created, as an RFC3339 datetime string.
     */
    readonly timeCreated: string;
    /**
     * When the project was updated, as an RFC3339 datetime string.
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Project resource in Oracle Cloud Infrastructure Ai Document service.
 *
 * Get a project by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testProject = oci.AiDocument.getProject({
 *     projectId: testProjectOciAiDocumentProject.id,
 * });
 * ```
 */
export function getProjectOutput(args: GetProjectOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetProjectResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:AiDocument/getProject:getProject", {
        "projectId": args.projectId,
    }, opts);
}

/**
 * A collection of arguments for invoking getProject.
 */
export interface GetProjectOutputArgs {
    /**
     * A unique project identifier.
     */
    projectId: pulumi.Input<string>;
}
