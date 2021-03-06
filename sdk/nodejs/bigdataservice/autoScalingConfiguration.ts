// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Auto Scaling Configuration resource in Oracle Cloud Infrastructure Big Data Service service.
 *
 * Add an autoscale configuration to the cluster.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutoScalingConfiguration = new oci.bigdataservice.AutoScalingConfiguration("testAutoScalingConfiguration", {
 *     bdsInstanceId: oci_bds_bds_instance.test_bds_instance.id,
 *     clusterAdminPassword: _var.auto_scaling_configuration_cluster_admin_password,
 *     isEnabled: _var.auto_scaling_configuration_is_enabled,
 *     nodeType: _var.auto_scaling_configuration_node_type,
 *     policy: {
 *         policyType: _var.auto_scaling_configuration_policy_policy_type,
 *         rules: [{
 *             action: _var.auto_scaling_configuration_policy_rules_action,
 *             metric: {
 *                 metricType: _var.auto_scaling_configuration_policy_rules_metric_metric_type,
 *                 threshold: {
 *                     durationInMinutes: _var.auto_scaling_configuration_policy_rules_metric_threshold_duration_in_minutes,
 *                     operator: _var.auto_scaling_configuration_policy_rules_metric_threshold_operator,
 *                     value: _var.auto_scaling_configuration_policy_rules_metric_threshold_value,
 *                 },
 *             },
 *         }],
 *     },
 *     displayName: _var.auto_scaling_configuration_display_name,
 * });
 * ```
 *
 * ## Import
 *
 * AutoScalingConfiguration can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:BigDataService/autoScalingConfiguration:AutoScalingConfiguration test_auto_scaling_configuration "bdsInstances/{bdsInstanceId}/autoScalingConfiguration/{autoScalingConfigurationId}"
 * ```
 */
export class AutoScalingConfiguration extends pulumi.CustomResource {
    /**
     * Get an existing AutoScalingConfiguration resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: AutoScalingConfigurationState, opts?: pulumi.CustomResourceOptions): AutoScalingConfiguration {
        return new AutoScalingConfiguration(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:BigDataService/autoScalingConfiguration:AutoScalingConfiguration';

    /**
     * Returns true if the given object is an instance of AutoScalingConfiguration.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is AutoScalingConfiguration {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === AutoScalingConfiguration.__pulumiType;
    }

    /**
     * The OCID of the cluster.
     */
    public readonly bdsInstanceId!: pulumi.Output<string>;
    /**
     * (Updatable) Base-64 encoded password for the cluster (and Cloudera Manager) admin user.
     */
    public readonly clusterAdminPassword!: pulumi.Output<string>;
    /**
     * (Updatable) A user-friendly name. The name does not have to be unique, and it may be changed. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Whether the autoscale configuration is enabled.
     */
    public readonly isEnabled!: pulumi.Output<boolean>;
    /**
     * A node type that is managed by an autoscale configuration. The only supported type is WORKER.
     */
    public readonly nodeType!: pulumi.Output<string>;
    /**
     * (Updatable) Policy definitions for the autoscale configuration.
     */
    public readonly policy!: pulumi.Output<outputs.BigDataService.AutoScalingConfigurationPolicy>;
    /**
     * The state of the autoscale configuration.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The time the cluster was created, shown as an RFC 3339 formatted datetime string.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time the autoscale configuration was updated, shown as an RFC 3339 formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a AutoScalingConfiguration resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: AutoScalingConfigurationArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: AutoScalingConfigurationArgs | AutoScalingConfigurationState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as AutoScalingConfigurationState | undefined;
            resourceInputs["bdsInstanceId"] = state ? state.bdsInstanceId : undefined;
            resourceInputs["clusterAdminPassword"] = state ? state.clusterAdminPassword : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["isEnabled"] = state ? state.isEnabled : undefined;
            resourceInputs["nodeType"] = state ? state.nodeType : undefined;
            resourceInputs["policy"] = state ? state.policy : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as AutoScalingConfigurationArgs | undefined;
            if ((!args || args.bdsInstanceId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'bdsInstanceId'");
            }
            if ((!args || args.clusterAdminPassword === undefined) && !opts.urn) {
                throw new Error("Missing required property 'clusterAdminPassword'");
            }
            if ((!args || args.isEnabled === undefined) && !opts.urn) {
                throw new Error("Missing required property 'isEnabled'");
            }
            if ((!args || args.nodeType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'nodeType'");
            }
            if ((!args || args.policy === undefined) && !opts.urn) {
                throw new Error("Missing required property 'policy'");
            }
            resourceInputs["bdsInstanceId"] = args ? args.bdsInstanceId : undefined;
            resourceInputs["clusterAdminPassword"] = args ? args.clusterAdminPassword : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["isEnabled"] = args ? args.isEnabled : undefined;
            resourceInputs["nodeType"] = args ? args.nodeType : undefined;
            resourceInputs["policy"] = args ? args.policy : undefined;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(AutoScalingConfiguration.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering AutoScalingConfiguration resources.
 */
export interface AutoScalingConfigurationState {
    /**
     * The OCID of the cluster.
     */
    bdsInstanceId?: pulumi.Input<string>;
    /**
     * (Updatable) Base-64 encoded password for the cluster (and Cloudera Manager) admin user.
     */
    clusterAdminPassword?: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly name. The name does not have to be unique, and it may be changed. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Whether the autoscale configuration is enabled.
     */
    isEnabled?: pulumi.Input<boolean>;
    /**
     * A node type that is managed by an autoscale configuration. The only supported type is WORKER.
     */
    nodeType?: pulumi.Input<string>;
    /**
     * (Updatable) Policy definitions for the autoscale configuration.
     */
    policy?: pulumi.Input<inputs.BigDataService.AutoScalingConfigurationPolicy>;
    /**
     * The state of the autoscale configuration.
     */
    state?: pulumi.Input<string>;
    /**
     * The time the cluster was created, shown as an RFC 3339 formatted datetime string.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time the autoscale configuration was updated, shown as an RFC 3339 formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a AutoScalingConfiguration resource.
 */
export interface AutoScalingConfigurationArgs {
    /**
     * The OCID of the cluster.
     */
    bdsInstanceId: pulumi.Input<string>;
    /**
     * (Updatable) Base-64 encoded password for the cluster (and Cloudera Manager) admin user.
     */
    clusterAdminPassword: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly name. The name does not have to be unique, and it may be changed. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Whether the autoscale configuration is enabled.
     */
    isEnabled: pulumi.Input<boolean>;
    /**
     * A node type that is managed by an autoscale configuration. The only supported type is WORKER.
     */
    nodeType: pulumi.Input<string>;
    /**
     * (Updatable) Policy definitions for the autoscale configuration.
     */
    policy: pulumi.Input<inputs.BigDataService.AutoScalingConfigurationPolicy>;
}
