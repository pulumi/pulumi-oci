// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Auto Scaling Configurations in Oracle Cloud Infrastructure Auto Scaling service.
 *
 * Lists autoscaling configurations in the specifed compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutoScalingConfigurations = oci.Autoscaling.getAutoScalingConfigurations({
 *     compartmentId: compartmentId,
 *     displayName: autoScalingConfigurationDisplayName,
 * });
 * ```
 */
export function getAutoScalingConfigurations(args: GetAutoScalingConfigurationsArgs, opts?: pulumi.InvokeOptions): Promise<GetAutoScalingConfigurationsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Autoscaling/getAutoScalingConfigurations:getAutoScalingConfigurations", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getAutoScalingConfigurations.
 */
export interface GetAutoScalingConfigurationsArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the resources monitored by the metric that you are searching for. Use tenancyId to search in the root compartment.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: string;
    filters?: inputs.Autoscaling.GetAutoScalingConfigurationsFilter[];
}

/**
 * A collection of values returned by getAutoScalingConfigurations.
 */
export interface GetAutoScalingConfigurationsResult {
    /**
     * The list of auto_scaling_configurations.
     */
    readonly autoScalingConfigurations: outputs.Autoscaling.GetAutoScalingConfigurationsAutoScalingConfiguration[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the autoscaling configuration.
     */
    readonly compartmentId: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly filters?: outputs.Autoscaling.GetAutoScalingConfigurationsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
}
/**
 * This data source provides the list of Auto Scaling Configurations in Oracle Cloud Infrastructure Auto Scaling service.
 *
 * Lists autoscaling configurations in the specifed compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutoScalingConfigurations = oci.Autoscaling.getAutoScalingConfigurations({
 *     compartmentId: compartmentId,
 *     displayName: autoScalingConfigurationDisplayName,
 * });
 * ```
 */
export function getAutoScalingConfigurationsOutput(args: GetAutoScalingConfigurationsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetAutoScalingConfigurationsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Autoscaling/getAutoScalingConfigurations:getAutoScalingConfigurations", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getAutoScalingConfigurations.
 */
export interface GetAutoScalingConfigurationsOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the resources monitored by the metric that you are searching for. Use tenancyId to search in the root compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Autoscaling.GetAutoScalingConfigurationsFilterArgs>[]>;
}
