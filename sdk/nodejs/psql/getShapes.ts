// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Shapes in Oracle Cloud Infrastructure Psql service.
 *
 * Returns the list of shapes allowed in the region.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testShapes = oci.Psql.getShapes({
 *     compartmentId: compartmentId,
 *     id: shapeId,
 * });
 * ```
 */
export function getShapes(args?: GetShapesArgs, opts?: pulumi.InvokeOptions): Promise<GetShapesResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Psql/getShapes:getShapes", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "id": args.id,
    }, opts);
}

/**
 * A collection of arguments for invoking getShapes.
 */
export interface GetShapesArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId?: string;
    filters?: inputs.Psql.GetShapesFilter[];
    /**
     * A filter to return the feature by the shape name.
     */
    id?: string;
}

/**
 * A collection of values returned by getShapes.
 */
export interface GetShapesResult {
    readonly compartmentId?: string;
    readonly filters?: outputs.Psql.GetShapesFilter[];
    /**
     * A unique identifier for the shape.
     */
    readonly id?: string;
    /**
     * The list of shape_collection.
     */
    readonly shapeCollections: outputs.Psql.GetShapesShapeCollection[];
}
/**
 * This data source provides the list of Shapes in Oracle Cloud Infrastructure Psql service.
 *
 * Returns the list of shapes allowed in the region.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testShapes = oci.Psql.getShapes({
 *     compartmentId: compartmentId,
 *     id: shapeId,
 * });
 * ```
 */
export function getShapesOutput(args?: GetShapesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetShapesResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Psql/getShapes:getShapes", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "id": args.id,
    }, opts);
}

/**
 * A collection of arguments for invoking getShapes.
 */
export interface GetShapesOutputArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Psql.GetShapesFilterArgs>[]>;
    /**
     * A filter to return the feature by the shape name.
     */
    id?: pulumi.Input<string>;
}
