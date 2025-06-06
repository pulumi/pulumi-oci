// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Addon resource in Oracle Cloud Infrastructure Container Engine service.
 *
 * Get the specified addon for a cluster.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAddon = oci.ContainerEngine.getAddon({
 *     addonName: testAddonOciContainerengineAddon.name,
 *     clusterId: testCluster.id,
 * });
 * ```
 */
export function getAddon(args: GetAddonArgs, opts?: pulumi.InvokeOptions): Promise<GetAddonResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:ContainerEngine/getAddon:getAddon", {
        "addonName": args.addonName,
        "clusterId": args.clusterId,
    }, opts);
}

/**
 * A collection of arguments for invoking getAddon.
 */
export interface GetAddonArgs {
    /**
     * The name of the addon.
     */
    addonName: string;
    /**
     * The OCID of the cluster.
     */
    clusterId: string;
}

/**
 * A collection of values returned by getAddon.
 */
export interface GetAddonResult {
    /**
     * The error info of the addon.
     */
    readonly addonErrors: outputs.ContainerEngine.GetAddonAddonError[];
    /**
     * The name of the addon.
     */
    readonly addonName: string;
    readonly clusterId: string;
    /**
     * Addon configuration details.
     */
    readonly configurations: outputs.ContainerEngine.GetAddonConfiguration[];
    /**
     * current installed version of the addon
     */
    readonly currentInstalledVersion: string;
    readonly id: string;
    readonly overrideExisting: boolean;
    readonly removeAddonResourcesOnDelete: boolean;
    /**
     * The state of the addon.
     */
    readonly state: string;
    /**
     * The time the cluster was created.
     */
    readonly timeCreated: string;
    /**
     * selected addon version, or null indicates autoUpdate
     */
    readonly version: string;
}
/**
 * This data source provides details about a specific Addon resource in Oracle Cloud Infrastructure Container Engine service.
 *
 * Get the specified addon for a cluster.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAddon = oci.ContainerEngine.getAddon({
 *     addonName: testAddonOciContainerengineAddon.name,
 *     clusterId: testCluster.id,
 * });
 * ```
 */
export function getAddonOutput(args: GetAddonOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetAddonResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:ContainerEngine/getAddon:getAddon", {
        "addonName": args.addonName,
        "clusterId": args.clusterId,
    }, opts);
}

/**
 * A collection of arguments for invoking getAddon.
 */
export interface GetAddonOutputArgs {
    /**
     * The name of the addon.
     */
    addonName: pulumi.Input<string>;
    /**
     * The OCID of the cluster.
     */
    clusterId: pulumi.Input<string>;
}
