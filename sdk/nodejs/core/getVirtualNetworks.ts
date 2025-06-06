// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

export function getVirtualNetworks(args: GetVirtualNetworksArgs, opts?: pulumi.InvokeOptions): Promise<GetVirtualNetworksResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Core/getVirtualNetworks:getVirtualNetworks", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getVirtualNetworks.
 */
export interface GetVirtualNetworksArgs {
    compartmentId: string;
    displayName?: string;
    filters?: inputs.Core.GetVirtualNetworksFilter[];
    state?: string;
}

/**
 * A collection of values returned by getVirtualNetworks.
 */
export interface GetVirtualNetworksResult {
    readonly compartmentId: string;
    readonly displayName?: string;
    readonly filters?: outputs.Core.GetVirtualNetworksFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly state?: string;
    readonly virtualNetworks: outputs.Core.GetVirtualNetworksVirtualNetwork[];
}
export function getVirtualNetworksOutput(args: GetVirtualNetworksOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetVirtualNetworksResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Core/getVirtualNetworks:getVirtualNetworks", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getVirtualNetworks.
 */
export interface GetVirtualNetworksOutputArgs {
    compartmentId: pulumi.Input<string>;
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Core.GetVirtualNetworksFilterArgs>[]>;
    state?: pulumi.Input<string>;
}
