// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Notebook Session Shapes in Oracle Cloud Infrastructure Data Science service.
 *
 * Lists the valid notebook session shapes.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNotebookSessionShapes = oci.DataScience.getNotebookSessionShapes({
 *     compartmentId: _var.compartment_id,
 * });
 * ```
 */
export function getNotebookSessionShapes(args: GetNotebookSessionShapesArgs, opts?: pulumi.InvokeOptions): Promise<GetNotebookSessionShapesResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:DataScience/getNotebookSessionShapes:getNotebookSessionShapes", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getNotebookSessionShapes.
 */
export interface GetNotebookSessionShapesArgs {
    /**
     * <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    filters?: inputs.DataScience.GetNotebookSessionShapesFilter[];
}

/**
 * A collection of values returned by getNotebookSessionShapes.
 */
export interface GetNotebookSessionShapesResult {
    readonly compartmentId: string;
    readonly filters?: outputs.DataScience.GetNotebookSessionShapesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of notebook_session_shapes.
     */
    readonly notebookSessionShapes: outputs.DataScience.GetNotebookSessionShapesNotebookSessionShape[];
}

export function getNotebookSessionShapesOutput(args: GetNotebookSessionShapesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetNotebookSessionShapesResult> {
    return pulumi.output(args).apply(a => getNotebookSessionShapes(a, opts))
}

/**
 * A collection of arguments for invoking getNotebookSessionShapes.
 */
export interface GetNotebookSessionShapesOutputArgs {
    /**
     * <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.DataScience.GetNotebookSessionShapesFilterArgs>[]>;
}