// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

export function getAutoScalingConfigurations(args: GetAutoScalingConfigurationsArgs, opts?: pulumi.InvokeOptions): Promise<GetAutoScalingConfigurationsResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:BigDataService/getAutoScalingConfigurations:getAutoScalingConfigurations", {
        "bdsInstanceId": args.bdsInstanceId,
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getAutoScalingConfigurations.
 */
export interface GetAutoScalingConfigurationsArgs {
    bdsInstanceId: string;
    compartmentId: string;
    displayName?: string;
    filters?: inputs.BigDataService.GetAutoScalingConfigurationsFilter[];
    state?: string;
}

/**
 * A collection of values returned by getAutoScalingConfigurations.
 */
export interface GetAutoScalingConfigurationsResult {
    readonly autoScalingConfigurations: outputs.BigDataService.GetAutoScalingConfigurationsAutoScalingConfiguration[];
    readonly bdsInstanceId: string;
    readonly compartmentId: string;
    readonly displayName?: string;
    readonly filters?: outputs.BigDataService.GetAutoScalingConfigurationsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly state?: string;
}

export function getAutoScalingConfigurationsOutput(args: GetAutoScalingConfigurationsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetAutoScalingConfigurationsResult> {
    return pulumi.output(args).apply(a => getAutoScalingConfigurations(a, opts))
}

/**
 * A collection of arguments for invoking getAutoScalingConfigurations.
 */
export interface GetAutoScalingConfigurationsOutputArgs {
    bdsInstanceId: pulumi.Input<string>;
    compartmentId: pulumi.Input<string>;
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.BigDataService.GetAutoScalingConfigurationsFilterArgs>[]>;
    state?: pulumi.Input<string>;
}
