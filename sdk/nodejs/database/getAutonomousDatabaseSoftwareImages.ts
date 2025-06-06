// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Autonomous Database Software Images in Oracle Cloud Infrastructure Database service.
 *
 * Gets a list of the Autonomous Database Software Images in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutonomousDatabaseSoftwareImages = oci.Database.getAutonomousDatabaseSoftwareImages({
 *     compartmentId: compartmentId,
 *     imageShapeFamily: autonomousDatabaseSoftwareImageImageShapeFamily,
 *     displayName: autonomousDatabaseSoftwareImageDisplayName,
 *     state: autonomousDatabaseSoftwareImageState,
 * });
 * ```
 */
export function getAutonomousDatabaseSoftwareImages(args: GetAutonomousDatabaseSoftwareImagesArgs, opts?: pulumi.InvokeOptions): Promise<GetAutonomousDatabaseSoftwareImagesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Database/getAutonomousDatabaseSoftwareImages:getAutonomousDatabaseSoftwareImages", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "imageShapeFamily": args.imageShapeFamily,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getAutonomousDatabaseSoftwareImages.
 */
export interface GetAutonomousDatabaseSoftwareImagesArgs {
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     */
    displayName?: string;
    filters?: inputs.Database.GetAutonomousDatabaseSoftwareImagesFilter[];
    /**
     * A filter to return only resources that match the given image shape family exactly.
     */
    imageShapeFamily: string;
    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     */
    state?: string;
}

/**
 * A collection of values returned by getAutonomousDatabaseSoftwareImages.
 */
export interface GetAutonomousDatabaseSoftwareImagesResult {
    /**
     * The list of autonomous_database_software_image_collection.
     */
    readonly autonomousDatabaseSoftwareImageCollections: outputs.Database.GetAutonomousDatabaseSoftwareImagesAutonomousDatabaseSoftwareImageCollection[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The user-friendly name for the Autonomous Database Software Image. The name does not have to be unique.
     */
    readonly displayName?: string;
    readonly filters?: outputs.Database.GetAutonomousDatabaseSoftwareImagesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * To what shape the image is meant for.
     */
    readonly imageShapeFamily: string;
    /**
     * The current state of the Autonomous Database Software Image.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Autonomous Database Software Images in Oracle Cloud Infrastructure Database service.
 *
 * Gets a list of the Autonomous Database Software Images in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutonomousDatabaseSoftwareImages = oci.Database.getAutonomousDatabaseSoftwareImages({
 *     compartmentId: compartmentId,
 *     imageShapeFamily: autonomousDatabaseSoftwareImageImageShapeFamily,
 *     displayName: autonomousDatabaseSoftwareImageDisplayName,
 *     state: autonomousDatabaseSoftwareImageState,
 * });
 * ```
 */
export function getAutonomousDatabaseSoftwareImagesOutput(args: GetAutonomousDatabaseSoftwareImagesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetAutonomousDatabaseSoftwareImagesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Database/getAutonomousDatabaseSoftwareImages:getAutonomousDatabaseSoftwareImages", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "imageShapeFamily": args.imageShapeFamily,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getAutonomousDatabaseSoftwareImages.
 */
export interface GetAutonomousDatabaseSoftwareImagesOutputArgs {
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Database.GetAutonomousDatabaseSoftwareImagesFilterArgs>[]>;
    /**
     * A filter to return only resources that match the given image shape family exactly.
     */
    imageShapeFamily: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     */
    state?: pulumi.Input<string>;
}
