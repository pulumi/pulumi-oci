// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Addons in Oracle Cloud Infrastructure Container Engine service.
 *
 * List addon for a provisioned cluster.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAddons = oci.ContainerEngine.getAddons({
 *     clusterId: testCluster.id,
 * });
 * ```
 */
export function getAddons(args: GetAddonsArgs, opts?: pulumi.InvokeOptions): Promise<GetAddonsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:ContainerEngine/getAddons:getAddons", {
        "clusterId": args.clusterId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getAddons.
 */
export interface GetAddonsArgs {
    /**
     * The OCID of the cluster.
     */
    clusterId: string;
    filters?: inputs.ContainerEngine.GetAddonsFilter[];
}

/**
 * A collection of values returned by getAddons.
 */
export interface GetAddonsResult {
    /**
     * The list of addons.
     */
    readonly addons: outputs.ContainerEngine.GetAddonsAddon[];
    readonly clusterId: string;
    readonly filters?: outputs.ContainerEngine.GetAddonsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
}
/**
 * This data source provides the list of Addons in Oracle Cloud Infrastructure Container Engine service.
 *
 * List addon for a provisioned cluster.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAddons = oci.ContainerEngine.getAddons({
 *     clusterId: testCluster.id,
 * });
 * ```
 */
export function getAddonsOutput(args: GetAddonsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetAddonsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:ContainerEngine/getAddons:getAddons", {
        "clusterId": args.clusterId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getAddons.
 */
export interface GetAddonsOutputArgs {
    /**
     * The OCID of the cluster.
     */
    clusterId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.ContainerEngine.GetAddonsFilterArgs>[]>;
}
