// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Work Request Errors in Oracle Cloud Infrastructure Container Engine service.
 *
 * Get the errors of a work request.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testWorkRequestErrors = oci.ContainerEngine.getWorkRequestErrors({
 *     compartmentId: _var.compartment_id,
 *     workRequestId: oci_containerengine_work_request.test_work_request.id,
 * });
 * ```
 */
export function getWorkRequestErrors(args: GetWorkRequestErrorsArgs, opts?: pulumi.InvokeOptions): Promise<GetWorkRequestErrorsResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:ContainerEngine/getWorkRequestErrors:getWorkRequestErrors", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "workRequestId": args.workRequestId,
    }, opts);
}

/**
 * A collection of arguments for invoking getWorkRequestErrors.
 */
export interface GetWorkRequestErrorsArgs {
    /**
     * The OCID of the compartment.
     */
    compartmentId: string;
    filters?: inputs.ContainerEngine.GetWorkRequestErrorsFilter[];
    /**
     * The OCID of the work request.
     */
    workRequestId: string;
}

/**
 * A collection of values returned by getWorkRequestErrors.
 */
export interface GetWorkRequestErrorsResult {
    readonly compartmentId: string;
    readonly filters?: outputs.ContainerEngine.GetWorkRequestErrorsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of work_request_errors.
     */
    readonly workRequestErrors: outputs.ContainerEngine.GetWorkRequestErrorsWorkRequestError[];
    readonly workRequestId: string;
}

export function getWorkRequestErrorsOutput(args: GetWorkRequestErrorsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetWorkRequestErrorsResult> {
    return pulumi.output(args).apply(a => getWorkRequestErrors(a, opts))
}

/**
 * A collection of arguments for invoking getWorkRequestErrors.
 */
export interface GetWorkRequestErrorsOutputArgs {
    /**
     * The OCID of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.ContainerEngine.GetWorkRequestErrorsFilterArgs>[]>;
    /**
     * The OCID of the work request.
     */
    workRequestId: pulumi.Input<string>;
}
