// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Object Lifecycle Policy resource in Oracle Cloud Infrastructure Object Storage service.
 *
 * Gets the object lifecycle policy for the bucket.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testObjectLifecyclePolicy = oci.ObjectStorage.getObjectLifecyclePolicy({
 *     bucket: _var.object_lifecycle_policy_bucket,
 *     namespace: _var.object_lifecycle_policy_namespace,
 * });
 * ```
 */
export function getObjectLifecyclePolicy(args: GetObjectLifecyclePolicyArgs, opts?: pulumi.InvokeOptions): Promise<GetObjectLifecyclePolicyResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:ObjectStorage/getObjectLifecyclePolicy:getObjectLifecyclePolicy", {
        "bucket": args.bucket,
        "namespace": args.namespace,
    }, opts);
}

/**
 * A collection of arguments for invoking getObjectLifecyclePolicy.
 */
export interface GetObjectLifecyclePolicyArgs {
    /**
     * The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
     */
    bucket: string;
    /**
     * The Object Storage namespace used for the request.
     */
    namespace: string;
}

/**
 * A collection of values returned by getObjectLifecyclePolicy.
 */
export interface GetObjectLifecyclePolicyResult {
    readonly bucket: string;
    readonly id: string;
    readonly namespace: string;
    /**
     * The live lifecycle policy on the bucket.
     */
    readonly rules: outputs.ObjectStorage.GetObjectLifecyclePolicyRule[];
    /**
     * The date and time the object lifecycle policy was created, as described in [RFC 3339](https://tools.ietf.org/html/rfc3339).
     */
    readonly timeCreated: string;
}

export function getObjectLifecyclePolicyOutput(args: GetObjectLifecyclePolicyOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetObjectLifecyclePolicyResult> {
    return pulumi.output(args).apply(a => getObjectLifecyclePolicy(a, opts))
}

/**
 * A collection of arguments for invoking getObjectLifecyclePolicy.
 */
export interface GetObjectLifecyclePolicyOutputArgs {
    /**
     * The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
     */
    bucket: pulumi.Input<string>;
    /**
     * The Object Storage namespace used for the request.
     */
    namespace: pulumi.Input<string>;
}
