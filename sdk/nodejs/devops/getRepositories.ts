// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Repositories in Oracle Cloud Infrastructure Devops service.
 *
 * Returns a list of repositories given a compartment ID or a project ID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRepositories = oci.DevOps.getRepositories({
 *     compartmentId: compartmentId,
 *     name: repositoryName,
 *     projectId: testProject.id,
 *     repositoryId: testRepository.id,
 *     state: repositoryState,
 * });
 * ```
 */
export function getRepositories(args?: GetRepositoriesArgs, opts?: pulumi.InvokeOptions): Promise<GetRepositoriesResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DevOps/getRepositories:getRepositories", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "name": args.name,
        "projectId": args.projectId,
        "repositoryId": args.repositoryId,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getRepositories.
 */
export interface GetRepositoriesArgs {
    /**
     * The OCID of the compartment in which to list resources.
     */
    compartmentId?: string;
    filters?: inputs.DevOps.GetRepositoriesFilter[];
    /**
     * A filter to return only resources that match the entire name given.
     */
    name?: string;
    /**
     * unique project identifier
     */
    projectId?: string;
    /**
     * Unique repository identifier.
     */
    repositoryId?: string;
    /**
     * A filter to return only resources whose lifecycle state matches the given lifecycle state.
     */
    state?: string;
}

/**
 * A collection of values returned by getRepositories.
 */
export interface GetRepositoriesResult {
    /**
     * The OCID of the repository's compartment.
     */
    readonly compartmentId?: string;
    readonly filters?: outputs.DevOps.GetRepositoriesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Name of the repository. Should be unique within the project. This value is mutable.
     */
    readonly name?: string;
    /**
     * The OCID of the DevOps project containing the repository.
     */
    readonly projectId?: string;
    /**
     * The list of repository_collection.
     */
    readonly repositoryCollections: outputs.DevOps.GetRepositoriesRepositoryCollection[];
    readonly repositoryId?: string;
    /**
     * The current state of the repository.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Repositories in Oracle Cloud Infrastructure Devops service.
 *
 * Returns a list of repositories given a compartment ID or a project ID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRepositories = oci.DevOps.getRepositories({
 *     compartmentId: compartmentId,
 *     name: repositoryName,
 *     projectId: testProject.id,
 *     repositoryId: testRepository.id,
 *     state: repositoryState,
 * });
 * ```
 */
export function getRepositoriesOutput(args?: GetRepositoriesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetRepositoriesResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DevOps/getRepositories:getRepositories", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "name": args.name,
        "projectId": args.projectId,
        "repositoryId": args.repositoryId,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getRepositories.
 */
export interface GetRepositoriesOutputArgs {
    /**
     * The OCID of the compartment in which to list resources.
     */
    compartmentId?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.DevOps.GetRepositoriesFilterArgs>[]>;
    /**
     * A filter to return only resources that match the entire name given.
     */
    name?: pulumi.Input<string>;
    /**
     * unique project identifier
     */
    projectId?: pulumi.Input<string>;
    /**
     * Unique repository identifier.
     */
    repositoryId?: pulumi.Input<string>;
    /**
     * A filter to return only resources whose lifecycle state matches the given lifecycle state.
     */
    state?: pulumi.Input<string>;
}
