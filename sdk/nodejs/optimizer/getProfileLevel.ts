// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Profile Level resource in Oracle Cloud Infrastructure Optimizer service.
 *
 * Lists the existing profile levels.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testProfileLevel = oci.Optimizer.getProfileLevel({
 *     compartmentId: compartmentId,
 *     compartmentIdInSubtree: profileLevelCompartmentIdInSubtree,
 *     name: profileLevelName,
 *     recommendationName: testRecommendation.name,
 * });
 * ```
 */
export function getProfileLevel(args: GetProfileLevelArgs, opts?: pulumi.InvokeOptions): Promise<GetProfileLevelResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Optimizer/getProfileLevel:getProfileLevel", {
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "name": args.name,
        "recommendationName": args.recommendationName,
    }, opts);
}

/**
 * A collection of arguments for invoking getProfileLevel.
 */
export interface GetProfileLevelArgs {
    /**
     * The OCID of the compartment.
     */
    compartmentId: string;
    /**
     * When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
     *
     * Can only be set to true when performing ListCompartments on the tenancy (root compartment).
     */
    compartmentIdInSubtree: boolean;
    /**
     * Optional. A filter that returns results that match the name specified.
     */
    name?: string;
    /**
     * Optional. A filter that returns results that match the recommendation name specified.
     */
    recommendationName?: string;
}

/**
 * A collection of values returned by getProfileLevel.
 */
export interface GetProfileLevelResult {
    readonly compartmentId: string;
    readonly compartmentIdInSubtree: boolean;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * A collection of profile levels.
     */
    readonly items: outputs.Optimizer.GetProfileLevelItem[];
    /**
     * A unique name for the profile level.
     */
    readonly name?: string;
    /**
     * The name of the recommendation this profile level applies to.
     */
    readonly recommendationName?: string;
}
/**
 * This data source provides details about a specific Profile Level resource in Oracle Cloud Infrastructure Optimizer service.
 *
 * Lists the existing profile levels.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testProfileLevel = oci.Optimizer.getProfileLevel({
 *     compartmentId: compartmentId,
 *     compartmentIdInSubtree: profileLevelCompartmentIdInSubtree,
 *     name: profileLevelName,
 *     recommendationName: testRecommendation.name,
 * });
 * ```
 */
export function getProfileLevelOutput(args: GetProfileLevelOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetProfileLevelResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Optimizer/getProfileLevel:getProfileLevel", {
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "name": args.name,
        "recommendationName": args.recommendationName,
    }, opts);
}

/**
 * A collection of arguments for invoking getProfileLevel.
 */
export interface GetProfileLevelOutputArgs {
    /**
     * The OCID of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
     *
     * Can only be set to true when performing ListCompartments on the tenancy (root compartment).
     */
    compartmentIdInSubtree: pulumi.Input<boolean>;
    /**
     * Optional. A filter that returns results that match the name specified.
     */
    name?: pulumi.Input<string>;
    /**
     * Optional. A filter that returns results that match the recommendation name specified.
     */
    recommendationName?: pulumi.Input<string>;
}
