// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Iam Work Requests in Oracle Cloud Infrastructure Identity service.
 *
 * List the IAM work requests in compartment
 *
 * - If IAM workrequest  details are retrieved sucessfully, return 202 ACCEPTED.
 * - If any internal error occurs, return 500 INTERNAL SERVER ERROR.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testIamWorkRequests = oci.Identity.getIamWorkRequests({
 *     compartmentId: compartmentId,
 *     resourceIdentifier: iamWorkRequestResourceIdentifier,
 * });
 * ```
 */
export function getIamWorkRequests(args: GetIamWorkRequestsArgs, opts?: pulumi.InvokeOptions): Promise<GetIamWorkRequestsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Identity/getIamWorkRequests:getIamWorkRequests", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "resourceIdentifier": args.resourceIdentifier,
    }, opts);
}

/**
 * A collection of arguments for invoking getIamWorkRequests.
 */
export interface GetIamWorkRequestsArgs {
    /**
     * The OCID of the compartment (remember that the tenancy is simply the root compartment).
     */
    compartmentId: string;
    filters?: inputs.Identity.GetIamWorkRequestsFilter[];
    /**
     * The identifier of the resource the work request affects.
     */
    resourceIdentifier?: string;
}

/**
 * A collection of values returned by getIamWorkRequests.
 */
export interface GetIamWorkRequestsResult {
    /**
     * The OCID of the compartment containing this IAM work request.
     */
    readonly compartmentId: string;
    readonly filters?: outputs.Identity.GetIamWorkRequestsFilter[];
    /**
     * The list of iam_work_requests.
     */
    readonly iamWorkRequests: outputs.Identity.GetIamWorkRequestsIamWorkRequest[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly resourceIdentifier?: string;
}
/**
 * This data source provides the list of Iam Work Requests in Oracle Cloud Infrastructure Identity service.
 *
 * List the IAM work requests in compartment
 *
 * - If IAM workrequest  details are retrieved sucessfully, return 202 ACCEPTED.
 * - If any internal error occurs, return 500 INTERNAL SERVER ERROR.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testIamWorkRequests = oci.Identity.getIamWorkRequests({
 *     compartmentId: compartmentId,
 *     resourceIdentifier: iamWorkRequestResourceIdentifier,
 * });
 * ```
 */
export function getIamWorkRequestsOutput(args: GetIamWorkRequestsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetIamWorkRequestsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Identity/getIamWorkRequests:getIamWorkRequests", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "resourceIdentifier": args.resourceIdentifier,
    }, opts);
}

/**
 * A collection of arguments for invoking getIamWorkRequests.
 */
export interface GetIamWorkRequestsOutputArgs {
    /**
     * The OCID of the compartment (remember that the tenancy is simply the root compartment).
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Identity.GetIamWorkRequestsFilterArgs>[]>;
    /**
     * The identifier of the resource the work request affects.
     */
    resourceIdentifier?: pulumi.Input<string>;
}
