// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Repository Archive Content resource in Oracle Cloud Infrastructure Devops service.
 *
 * Returns the archived repository information.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRepositoryArchiveContent = oci.DevOps.getRepositoryArchiveContent({
 *     repositoryId: testRepository.id,
 *     format: repositoryArchiveContentFormat,
 *     refName: repositoryArchiveContentRefName,
 * });
 * ```
 */
export function getRepositoryArchiveContent(args: GetRepositoryArchiveContentArgs, opts?: pulumi.InvokeOptions): Promise<GetRepositoryArchiveContentResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DevOps/getRepositoryArchiveContent:getRepositoryArchiveContent", {
        "format": args.format,
        "refName": args.refName,
        "repositoryId": args.repositoryId,
    }, opts);
}

/**
 * A collection of arguments for invoking getRepositoryArchiveContent.
 */
export interface GetRepositoryArchiveContentArgs {
    /**
     * The archive format query parameter for downloading repository endpoint.
     */
    format?: string;
    /**
     * A filter to return only resources that match the given reference name.
     */
    refName?: string;
    /**
     * Unique repository identifier.
     */
    repositoryId: string;
}

/**
 * A collection of values returned by getRepositoryArchiveContent.
 */
export interface GetRepositoryArchiveContentResult {
    readonly format?: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly refName?: string;
    readonly repositoryId: string;
}
/**
 * This data source provides details about a specific Repository Archive Content resource in Oracle Cloud Infrastructure Devops service.
 *
 * Returns the archived repository information.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRepositoryArchiveContent = oci.DevOps.getRepositoryArchiveContent({
 *     repositoryId: testRepository.id,
 *     format: repositoryArchiveContentFormat,
 *     refName: repositoryArchiveContentRefName,
 * });
 * ```
 */
export function getRepositoryArchiveContentOutput(args: GetRepositoryArchiveContentOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetRepositoryArchiveContentResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DevOps/getRepositoryArchiveContent:getRepositoryArchiveContent", {
        "format": args.format,
        "refName": args.refName,
        "repositoryId": args.repositoryId,
    }, opts);
}

/**
 * A collection of arguments for invoking getRepositoryArchiveContent.
 */
export interface GetRepositoryArchiveContentOutputArgs {
    /**
     * The archive format query parameter for downloading repository endpoint.
     */
    format?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given reference name.
     */
    refName?: pulumi.Input<string>;
    /**
     * Unique repository identifier.
     */
    repositoryId: pulumi.Input<string>;
}
