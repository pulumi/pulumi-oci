// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Repository Mirror Records in Oracle Cloud Infrastructure Devops service.
 *
 * Returns a list of mirror entry in history within 30 days.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRepositoryMirrorRecords = oci.DevOps.getRepositoryMirrorRecords({
 *     repositoryId: oci_devops_repository.test_repository.id,
 * });
 * ```
 */
export function getRepositoryMirrorRecords(args: GetRepositoryMirrorRecordsArgs, opts?: pulumi.InvokeOptions): Promise<GetRepositoryMirrorRecordsResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:DevOps/getRepositoryMirrorRecords:getRepositoryMirrorRecords", {
        "filters": args.filters,
        "repositoryId": args.repositoryId,
    }, opts);
}

/**
 * A collection of arguments for invoking getRepositoryMirrorRecords.
 */
export interface GetRepositoryMirrorRecordsArgs {
    filters?: inputs.DevOps.GetRepositoryMirrorRecordsFilter[];
    /**
     * Unique repository identifier.
     */
    repositoryId: string;
}

/**
 * A collection of values returned by getRepositoryMirrorRecords.
 */
export interface GetRepositoryMirrorRecordsResult {
    readonly filters?: outputs.DevOps.GetRepositoryMirrorRecordsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly repositoryId: string;
    /**
     * The list of repository_mirror_record_collection.
     */
    readonly repositoryMirrorRecordCollections: outputs.DevOps.GetRepositoryMirrorRecordsRepositoryMirrorRecordCollection[];
}

export function getRepositoryMirrorRecordsOutput(args: GetRepositoryMirrorRecordsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetRepositoryMirrorRecordsResult> {
    return pulumi.output(args).apply(a => getRepositoryMirrorRecords(a, opts))
}

/**
 * A collection of arguments for invoking getRepositoryMirrorRecords.
 */
export interface GetRepositoryMirrorRecordsOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.DevOps.GetRepositoryMirrorRecordsFilterArgs>[]>;
    /**
     * Unique repository identifier.
     */
    repositoryId: pulumi.Input<string>;
}