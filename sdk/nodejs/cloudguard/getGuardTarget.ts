// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Target resource in Oracle Cloud Infrastructure Cloud Guard service.
 *
 * Returns a Target identified by targetId
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testTarget = oci.CloudGuard.getGuardTarget({
 *     targetId: oci_cloud_guard_target.test_target.id,
 * });
 * ```
 */
export function getGuardTarget(args: GetGuardTargetArgs, opts?: pulumi.InvokeOptions): Promise<GetGuardTargetResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:CloudGuard/getGuardTarget:getGuardTarget", {
        "targetId": args.targetId,
    }, opts);
}

/**
 * A collection of arguments for invoking getGuardTarget.
 */
export interface GetGuardTargetArgs {
    /**
     * OCID of target
     */
    targetId: string;
}

/**
 * A collection of values returned by getGuardTarget.
 */
export interface GetGuardTargetResult {
    /**
     * Compartment Identifier
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * ResponderRule description.
     */
    readonly description: string;
    /**
     * ResponderRule display name.
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * Unique identifier of TargetResponderRecipe that can't be changed after creation.
     */
    readonly id: string;
    /**
     * List of inherited compartments
     */
    readonly inheritedByCompartments: string[];
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    readonly lifecyleDetails: string;
    /**
     * Total number of recipes attached to target
     */
    readonly recipeCount: number;
    /**
     * The current state of the ResponderRule.
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * Details specific to the target type.
     */
    readonly targetDetails: outputs.CloudGuard.GetGuardTargetTargetDetail[];
    /**
     * List of detector recipes associated with target
     */
    readonly targetDetectorRecipes: outputs.CloudGuard.GetGuardTargetTargetDetectorRecipe[];
    readonly targetId: string;
    /**
     * Resource ID which the target uses to monitor
     */
    readonly targetResourceId: string;
    /**
     * possible type of targets
     */
    readonly targetResourceType: string;
    /**
     * List of responder recipes associated with target
     */
    readonly targetResponderRecipes: outputs.CloudGuard.GetGuardTargetTargetResponderRecipe[];
    /**
     * The date and time the target was created. Format defined by RFC3339.
     */
    readonly timeCreated: string;
    /**
     * The date and time the target was updated. Format defined by RFC3339.
     */
    readonly timeUpdated: string;
}

export function getGuardTargetOutput(args: GetGuardTargetOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetGuardTargetResult> {
    return pulumi.output(args).apply(a => getGuardTarget(a, opts))
}

/**
 * A collection of arguments for invoking getGuardTarget.
 */
export interface GetGuardTargetOutputArgs {
    /**
     * OCID of target
     */
    targetId: pulumi.Input<string>;
}