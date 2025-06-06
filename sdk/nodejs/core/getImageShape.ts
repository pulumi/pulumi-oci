// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Image Shape resource in Oracle Cloud Infrastructure Core service.
 *
 * Retrieves an image shape compatibility entry.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testImageShape = oci.Core.getImageShape({
 *     imageId: testImage.id,
 *     shapeName: testShape.name,
 * });
 * ```
 */
export function getImageShape(args: GetImageShapeArgs, opts?: pulumi.InvokeOptions): Promise<GetImageShapeResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Core/getImageShape:getImageShape", {
        "imageId": args.imageId,
        "shapeName": args.shapeName,
    }, opts);
}

/**
 * A collection of arguments for invoking getImageShape.
 */
export interface GetImageShapeArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the image.
     */
    imageId: string;
    /**
     * Shape name.
     */
    shapeName: string;
}

/**
 * A collection of values returned by getImageShape.
 */
export interface GetImageShapeResult {
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    readonly imageId: string;
    /**
     * For a flexible image and shape, the amount of memory supported for instances that use this image.
     */
    readonly memoryConstraints: outputs.Core.GetImageShapeMemoryConstraint[];
    /**
     * OCPU options for an image and shape.
     */
    readonly ocpuConstraints: outputs.Core.GetImageShapeOcpuConstraint[];
    /**
     * The shape name.
     */
    readonly shape: string;
    readonly shapeName: string;
}
/**
 * This data source provides details about a specific Image Shape resource in Oracle Cloud Infrastructure Core service.
 *
 * Retrieves an image shape compatibility entry.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testImageShape = oci.Core.getImageShape({
 *     imageId: testImage.id,
 *     shapeName: testShape.name,
 * });
 * ```
 */
export function getImageShapeOutput(args: GetImageShapeOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetImageShapeResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Core/getImageShape:getImageShape", {
        "imageId": args.imageId,
        "shapeName": args.shapeName,
    }, opts);
}

/**
 * A collection of arguments for invoking getImageShape.
 */
export interface GetImageShapeOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the image.
     */
    imageId: pulumi.Input<string>;
    /**
     * Shape name.
     */
    shapeName: pulumi.Input<string>;
}
