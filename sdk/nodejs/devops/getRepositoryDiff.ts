// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Repository Diff resource in Oracle Cloud Infrastructure Devops service.
 *
 * Gets the line-by-line difference between file on different commits. This API will be deprecated on Wed, 29 Mar 2023 01:00:00 GMT as it does not get recognized when filePath has '/'. This will be replaced by "/repositories/{repositoryId}/file/diffs"
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRepositoryDiff = oci.DevOps.getRepositoryDiff({
 *     baseVersion: _var.repository_diff_base_version,
 *     filePath: _var.repository_diff_file_path,
 *     repositoryId: oci_devops_repository.test_repository.id,
 *     targetVersion: _var.repository_diff_target_version,
 *     isComparisonFromMergeBase: _var.repository_diff_is_comparison_from_merge_base,
 * });
 * ```
 */
export function getRepositoryDiff(args: GetRepositoryDiffArgs, opts?: pulumi.InvokeOptions): Promise<GetRepositoryDiffResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:DevOps/getRepositoryDiff:getRepositoryDiff", {
        "baseVersion": args.baseVersion,
        "filePath": args.filePath,
        "isComparisonFromMergeBase": args.isComparisonFromMergeBase,
        "repositoryId": args.repositoryId,
        "targetVersion": args.targetVersion,
    }, opts);
}

/**
 * A collection of arguments for invoking getRepositoryDiff.
 */
export interface GetRepositoryDiffArgs {
    /**
     * The branch to compare changes against.
     */
    baseVersion: string;
    /**
     * Path to a file within a repository.
     */
    filePath: string;
    /**
     * Boolean to indicate whether to use merge base or most recent revision.
     */
    isComparisonFromMergeBase?: boolean;
    /**
     * Unique repository identifier.
     */
    repositoryId: string;
    /**
     * The branch where changes are coming from.
     */
    targetVersion: string;
}

/**
 * A collection of values returned by getRepositoryDiff.
 */
export interface GetRepositoryDiffResult {
    /**
     * Indicates whether the changed file contains conflicts.
     */
    readonly areConflictsInFile: boolean;
    readonly baseVersion: string;
    /**
     * List of changed section in the file.
     */
    readonly changes: outputs.DevOps.GetRepositoryDiffChange[];
    readonly filePath: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Indicates whether the file is binary.
     */
    readonly isBinary: boolean;
    readonly isComparisonFromMergeBase?: boolean;
    /**
     * Indicates whether the file is large.
     */
    readonly isLarge: boolean;
    /**
     * The ID of the changed object on the target version.
     */
    readonly newId: string;
    /**
     * The path on the target version to the changed object.
     */
    readonly newPath: string;
    /**
     * The ID of the changed object on the base version.
     */
    readonly oldId: string;
    /**
     * The path on the base version to the changed object.
     */
    readonly oldPath: string;
    readonly repositoryId: string;
    readonly targetVersion: string;
}

export function getRepositoryDiffOutput(args: GetRepositoryDiffOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetRepositoryDiffResult> {
    return pulumi.output(args).apply(a => getRepositoryDiff(a, opts))
}

/**
 * A collection of arguments for invoking getRepositoryDiff.
 */
export interface GetRepositoryDiffOutputArgs {
    /**
     * The branch to compare changes against.
     */
    baseVersion: pulumi.Input<string>;
    /**
     * Path to a file within a repository.
     */
    filePath: pulumi.Input<string>;
    /**
     * Boolean to indicate whether to use merge base or most recent revision.
     */
    isComparisonFromMergeBase?: pulumi.Input<boolean>;
    /**
     * Unique repository identifier.
     */
    repositoryId: pulumi.Input<string>;
    /**
     * The branch where changes are coming from.
     */
    targetVersion: pulumi.Input<string>;
}