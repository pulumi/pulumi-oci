// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Auto Scaling Configuration resource in Oracle Cloud Infrastructure Big Data Service service.
 *
 * Returns details of the autoscale configuration identified by the given ID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutoScalingConfiguration = oci.BigDataService.getAutoScalingConfiguration({
 *     autoScalingConfigurationId: oci_autoscaling_auto_scaling_configuration.test_auto_scaling_configuration.id,
 *     bdsInstanceId: oci_bds_bds_instance.test_bds_instance.id,
 * });
 * ```
 */
export function getAutoScalingConfiguration(args: GetAutoScalingConfigurationArgs, opts?: pulumi.InvokeOptions): Promise<GetAutoScalingConfigurationResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:BigDataService/getAutoScalingConfiguration:getAutoScalingConfiguration", {
        "autoScalingConfigurationId": args.autoScalingConfigurationId,
        "bdsInstanceId": args.bdsInstanceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getAutoScalingConfiguration.
 */
export interface GetAutoScalingConfigurationArgs {
    /**
     * Unique Oracle-assigned identifier of the autoscale configuration.
     */
    autoScalingConfigurationId: string;
    /**
     * The OCID of the cluster.
     */
    bdsInstanceId: string;
}

/**
 * A collection of values returned by getAutoScalingConfiguration.
 */
export interface GetAutoScalingConfigurationResult {
    readonly autoScalingConfigurationId: string;
    readonly bdsInstanceId: string;
    readonly clusterAdminPassword: string;
    /**
     * A user-friendly name. The name does not have to be unique, and it may be changed. Avoid entering confidential information.
     */
    readonly displayName: string;
    /**
     * The unique identifier for the autoscale configuration.
     */
    readonly id: string;
    readonly isEnabled: boolean;
    /**
     * A node type that is managed by an autoscale configuration. The only supported types are WORKER and COMPUTE_ONLY_WORKER.
     */
    readonly nodeType: string;
    /**
     * This model for autoscaling policy is deprecated and not supported for ODH clusters. Use the `AutoScalePolicyDetails` model to manage autoscale policy details for ODH clusters.
     */
    readonly policies: outputs.BigDataService.GetAutoScalingConfigurationPolicy[];
    /**
     * Details of an autoscale policy.
     */
    readonly policyDetails: outputs.BigDataService.GetAutoScalingConfigurationPolicyDetail[];
    /**
     * The state of the autoscale configuration.
     */
    readonly state: string;
    /**
     * The time the cluster was created, shown as an RFC 3339 formatted datetime string.
     */
    readonly timeCreated: string;
    /**
     * The time the autoscale configuration was updated, shown as an RFC 3339 formatted datetime string.
     */
    readonly timeUpdated: string;
}

export function getAutoScalingConfigurationOutput(args: GetAutoScalingConfigurationOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetAutoScalingConfigurationResult> {
    return pulumi.output(args).apply(a => getAutoScalingConfiguration(a, opts))
}

/**
 * A collection of arguments for invoking getAutoScalingConfiguration.
 */
export interface GetAutoScalingConfigurationOutputArgs {
    /**
     * Unique Oracle-assigned identifier of the autoscale configuration.
     */
    autoScalingConfigurationId: pulumi.Input<string>;
    /**
     * The OCID of the cluster.
     */
    bdsInstanceId: pulumi.Input<string>;
}