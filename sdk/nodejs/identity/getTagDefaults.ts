// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Tag Defaults in Oracle Cloud Infrastructure Identity service.
 *
 * Lists the tag defaults for tag definitions in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testTagDefaults = oci.Identity.getTagDefaults({
 *     compartmentId: compartmentId,
 *     id: tagDefaultId,
 *     state: tagDefaultState,
 *     tagDefinitionId: testTagDefinition.id,
 * });
 * ```
 */
export function getTagDefaults(args?: GetTagDefaultsArgs, opts?: pulumi.InvokeOptions): Promise<GetTagDefaultsResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Identity/getTagDefaults:getTagDefaults", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "id": args.id,
        "state": args.state,
        "tagDefinitionId": args.tagDefinitionId,
    }, opts);
}

/**
 * A collection of arguments for invoking getTagDefaults.
 */
export interface GetTagDefaultsArgs {
    /**
     * The OCID of the compartment (remember that the tenancy is simply the root compartment).
     */
    compartmentId?: string;
    filters?: inputs.Identity.GetTagDefaultsFilter[];
    /**
     * A filter to only return resources that match the specified OCID exactly.
     */
    id?: string;
    /**
     * A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     */
    state?: string;
    /**
     * The OCID of the tag definition.
     */
    tagDefinitionId?: string;
}

/**
 * A collection of values returned by getTagDefaults.
 */
export interface GetTagDefaultsResult {
    /**
     * The OCID of the compartment. The tag default applies to all new resources that get created in the compartment. Resources that existed before the tag default was created are not tagged.
     */
    readonly compartmentId?: string;
    readonly filters?: outputs.Identity.GetTagDefaultsFilter[];
    /**
     * The OCID of the tag default.
     */
    readonly id?: string;
    /**
     * The tag default's current state. After creating a `TagDefault`, make sure its `lifecycleState` is ACTIVE before using it.
     */
    readonly state?: string;
    /**
     * The list of tag_defaults.
     */
    readonly tagDefaults: outputs.Identity.GetTagDefaultsTagDefault[];
    /**
     * The OCID of the tag definition. The tag default will always assign a default value for this tag definition.
     */
    readonly tagDefinitionId?: string;
}
/**
 * This data source provides the list of Tag Defaults in Oracle Cloud Infrastructure Identity service.
 *
 * Lists the tag defaults for tag definitions in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testTagDefaults = oci.Identity.getTagDefaults({
 *     compartmentId: compartmentId,
 *     id: tagDefaultId,
 *     state: tagDefaultState,
 *     tagDefinitionId: testTagDefinition.id,
 * });
 * ```
 */
export function getTagDefaultsOutput(args?: GetTagDefaultsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetTagDefaultsResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Identity/getTagDefaults:getTagDefaults", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "id": args.id,
        "state": args.state,
        "tagDefinitionId": args.tagDefinitionId,
    }, opts);
}

/**
 * A collection of arguments for invoking getTagDefaults.
 */
export interface GetTagDefaultsOutputArgs {
    /**
     * The OCID of the compartment (remember that the tenancy is simply the root compartment).
     */
    compartmentId?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Identity.GetTagDefaultsFilterArgs>[]>;
    /**
     * A filter to only return resources that match the specified OCID exactly.
     */
    id?: pulumi.Input<string>;
    /**
     * A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     */
    state?: pulumi.Input<string>;
    /**
     * The OCID of the tag definition.
     */
    tagDefinitionId?: pulumi.Input<string>;
}
