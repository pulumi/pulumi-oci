// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Job Output resource in Oracle Cloud Infrastructure Database Migration service.
 *
 * List the Job Outputs
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testJobOutput = oci.DatabaseMigration.getJobOutput({
 *     jobId: oci_database_migration_job.test_job.id,
 * });
 * ```
 */
export function getJobOutput(args: GetJobOutputArgs, opts?: pulumi.InvokeOptions): Promise<GetJobOutputResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:DatabaseMigration/getJobOutput:getJobOutput", {
        "jobId": args.jobId,
    }, opts);
}

/**
 * A collection of arguments for invoking getJobOutput.
 */
export interface GetJobOutputArgs {
    /**
     * The OCID of the job
     */
    jobId: string;
}

/**
 * A collection of values returned by getJobOutput.
 */
export interface GetJobOutputResult {
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Items in collection.
     */
    readonly items: outputs.DatabaseMigration.GetJobOutputItem[];
    readonly jobId: string;
}

export function getJobOutputOutput(args: GetJobOutputOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetJobOutputResult> {
    return pulumi.output(args).apply(a => getJobOutput(a, opts))
}

/**
 * A collection of arguments for invoking getJobOutput.
 */
export interface GetJobOutputOutputArgs {
    /**
     * The OCID of the job
     */
    jobId: pulumi.Input<string>;
}
