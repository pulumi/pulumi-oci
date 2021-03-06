// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

export function getVirtualNetworks(args: GetVirtualNetworksArgs, opts?: pulumi.InvokeOptions): Promise<GetVirtualNetworksResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
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

export function getVirtualNetworksOutput(args: GetVirtualNetworksOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetVirtualNetworksResult> {
    return pulumi.output(args).apply(a => getVirtualNetworks(a, opts))
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
