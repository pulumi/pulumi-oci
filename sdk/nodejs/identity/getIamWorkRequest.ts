// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Iam Work Request resource in Oracle Cloud Infrastructure Identity service.
 *
 * Gets details on a specified IAM work request. For asynchronous operations in Identity and Access Management service, opc-work-request-id header values contains
 * iam work request id that can be provided in this API to track the current status of the operation.
 *
 * - If workrequest exists, returns 202 ACCEPTED
 * - If workrequest does not exist, returns 404 NOT FOUND
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testIamWorkRequest = oci.Identity.getIamWorkRequest({
 *     iamWorkRequestId: oci_identity_iam_work_request.test_iam_work_request.id,
 * });
 * ```
 */
export function getIamWorkRequest(args: GetIamWorkRequestArgs, opts?: pulumi.InvokeOptions): Promise<GetIamWorkRequestResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Identity/getIamWorkRequest:getIamWorkRequest", {
        "iamWorkRequestId": args.iamWorkRequestId,
    }, opts);
}

/**
 * A collection of arguments for invoking getIamWorkRequest.
 */
export interface GetIamWorkRequestArgs {
    /**
     * The OCID of the IAM work request.
     */
    iamWorkRequestId: string;
}

/**
 * A collection of values returned by getIamWorkRequest.
 */
export interface GetIamWorkRequestResult {
    /**
     * The OCID of the compartment containing this IAM work request.
     */
    readonly compartmentId: string;
    readonly iamWorkRequestId: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The asynchronous operation tracked by this IAM work request.
     */
    readonly operationType: string;
    /**
     * How much progress the operation has made.
     */
    readonly percentComplete: number;
    /**
     * The resources this work request affects.
     */
    readonly resources: outputs.Identity.GetIamWorkRequestResource[];
    /**
     * Status of the work request
     */
    readonly status: string;
    /**
     * Date and time the work was accepted, in the format defined by RFC3339. Example: `2016-08-25T21:10:29.600Z`
     */
    readonly timeAccepted: string;
    /**
     * Date and time the work completed, in the format defined by RFC3339. Example: `2016-08-25T21:10:29.600Z`
     */
    readonly timeFinished: string;
    /**
     * Date and time the work started, in the format defined by RFC3339. Example: `2016-08-25T21:10:29.600Z`
     */
    readonly timeStarted: string;
}

export function getIamWorkRequestOutput(args: GetIamWorkRequestOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetIamWorkRequestResult> {
    return pulumi.output(args).apply(a => getIamWorkRequest(a, opts))
}

/**
 * A collection of arguments for invoking getIamWorkRequest.
 */
export interface GetIamWorkRequestOutputArgs {
    /**
     * The OCID of the IAM work request.
     */
    iamWorkRequestId: pulumi.Input<string>;
}