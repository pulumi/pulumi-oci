// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Iam Work Request Errors in Oracle Cloud Infrastructure Identity service.
 *
 * Gets error details for a specified IAM work request. For asynchronous operations in Identity and Access Management service, opc-work-request-id header values contains
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
 * const testIamWorkRequestErrors = oci.Identity.getIamWorkRequestErrors({
 *     iamWorkRequestId: testIamWorkRequest.id,
 * });
 * ```
 */
export function getIamWorkRequestErrors(args: GetIamWorkRequestErrorsArgs, opts?: pulumi.InvokeOptions): Promise<GetIamWorkRequestErrorsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Identity/getIamWorkRequestErrors:getIamWorkRequestErrors", {
        "filters": args.filters,
        "iamWorkRequestId": args.iamWorkRequestId,
    }, opts);
}

/**
 * A collection of arguments for invoking getIamWorkRequestErrors.
 */
export interface GetIamWorkRequestErrorsArgs {
    filters?: inputs.Identity.GetIamWorkRequestErrorsFilter[];
    /**
     * The OCID of the IAM work request.
     */
    iamWorkRequestId: string;
}

/**
 * A collection of values returned by getIamWorkRequestErrors.
 */
export interface GetIamWorkRequestErrorsResult {
    readonly filters?: outputs.Identity.GetIamWorkRequestErrorsFilter[];
    /**
     * The list of iam_work_request_errors.
     */
    readonly iamWorkRequestErrors: outputs.Identity.GetIamWorkRequestErrorsIamWorkRequestError[];
    readonly iamWorkRequestId: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
}
/**
 * This data source provides the list of Iam Work Request Errors in Oracle Cloud Infrastructure Identity service.
 *
 * Gets error details for a specified IAM work request. For asynchronous operations in Identity and Access Management service, opc-work-request-id header values contains
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
 * const testIamWorkRequestErrors = oci.Identity.getIamWorkRequestErrors({
 *     iamWorkRequestId: testIamWorkRequest.id,
 * });
 * ```
 */
export function getIamWorkRequestErrorsOutput(args: GetIamWorkRequestErrorsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetIamWorkRequestErrorsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Identity/getIamWorkRequestErrors:getIamWorkRequestErrors", {
        "filters": args.filters,
        "iamWorkRequestId": args.iamWorkRequestId,
    }, opts);
}

/**
 * A collection of arguments for invoking getIamWorkRequestErrors.
 */
export interface GetIamWorkRequestErrorsOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.Identity.GetIamWorkRequestErrorsFilterArgs>[]>;
    /**
     * The OCID of the IAM work request.
     */
    iamWorkRequestId: pulumi.Input<string>;
}
