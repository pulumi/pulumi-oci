// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Repository Mirror Record resource in Oracle Cloud Infrastructure Devops service.
 *
 * Returns either current mirror record or last successful mirror record for a specific mirror repository.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRepositoryMirrorRecord = oci.DevOps.getRepositoryMirrorRecord({
 *     mirrorRecordType: repositoryMirrorRecordMirrorRecordType,
 *     repositoryId: testRepository.id,
 * });
 * ```
 */
export function getRepositoryMirrorRecord(args: GetRepositoryMirrorRecordArgs, opts?: pulumi.InvokeOptions): Promise<GetRepositoryMirrorRecordResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DevOps/getRepositoryMirrorRecord:getRepositoryMirrorRecord", {
        "mirrorRecordType": args.mirrorRecordType,
        "repositoryId": args.repositoryId,
    }, opts);
}

/**
 * A collection of arguments for invoking getRepositoryMirrorRecord.
 */
export interface GetRepositoryMirrorRecordArgs {
    /**
     * The field of mirror record type. Only one mirror record type can be provided: current - The current mirror record. lastSuccessful - The last successful mirror record.
     */
    mirrorRecordType: string;
    /**
     * Unique repository identifier.
     */
    repositoryId: string;
}

/**
 * A collection of values returned by getRepositoryMirrorRecord.
 */
export interface GetRepositoryMirrorRecordResult {
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly mirrorRecordType: string;
    /**
     * Mirror status of current mirror entry. QUEUED - Mirroring Queued RUNNING - Mirroring is Running PASSED - Mirroring Passed FAILED - Mirroring Failed
     */
    readonly mirrorStatus: string;
    readonly repositoryId: string;
    /**
     * The time taken to complete a mirror operation. Value is null if not completed.
     */
    readonly timeEnded: string;
    /**
     * The time to enqueue a mirror operation.
     */
    readonly timeEnqueued: string;
    /**
     * The time to start a mirror operation.
     */
    readonly timeStarted: string;
    /**
     * Workrequest ID to track current mirror operation.
     */
    readonly workRequestId: string;
}
/**
 * This data source provides details about a specific Repository Mirror Record resource in Oracle Cloud Infrastructure Devops service.
 *
 * Returns either current mirror record or last successful mirror record for a specific mirror repository.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRepositoryMirrorRecord = oci.DevOps.getRepositoryMirrorRecord({
 *     mirrorRecordType: repositoryMirrorRecordMirrorRecordType,
 *     repositoryId: testRepository.id,
 * });
 * ```
 */
export function getRepositoryMirrorRecordOutput(args: GetRepositoryMirrorRecordOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetRepositoryMirrorRecordResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DevOps/getRepositoryMirrorRecord:getRepositoryMirrorRecord", {
        "mirrorRecordType": args.mirrorRecordType,
        "repositoryId": args.repositoryId,
    }, opts);
}

/**
 * A collection of arguments for invoking getRepositoryMirrorRecord.
 */
export interface GetRepositoryMirrorRecordOutputArgs {
    /**
     * The field of mirror record type. Only one mirror record type can be provided: current - The current mirror record. lastSuccessful - The last successful mirror record.
     */
    mirrorRecordType: pulumi.Input<string>;
    /**
     * Unique repository identifier.
     */
    repositoryId: pulumi.Input<string>;
}
