// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Monitor Plugin Management resource in Oracle Cloud Infrastructure Appmgmt Control service.
 *
 * Activates Resource Plugin for compute instance identified by the instance ocid.
 * Stores monitored instances Id and its state. Tries to enable Resource Monitoring plugin by making
 * remote calls to Oracle Cloud Agent and Management Agent Cloud Service.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMonitorPluginManagement = new oci.appmgmtcontrol.MonitorPluginManagement("test_monitor_plugin_management", {monitoredInstanceId: testMonitoredInstance.id});
 * ```
 *
 * ## Import
 *
 * Import is not supported for this resource.
 */
export class MonitorPluginManagement extends pulumi.CustomResource {
    /**
     * Get an existing MonitorPluginManagement resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: MonitorPluginManagementState, opts?: pulumi.CustomResourceOptions): MonitorPluginManagement {
        return new MonitorPluginManagement(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:AppMgmtControl/monitorPluginManagement:MonitorPluginManagement';

    /**
     * Returns true if the given object is an instance of MonitorPluginManagement.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is MonitorPluginManagement {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === MonitorPluginManagement.__pulumiType;
    }

    public /*out*/ readonly compartmentId!: pulumi.Output<string>;
    public /*out*/ readonly monitoredInstanceDescription!: pulumi.Output<string>;
    public /*out*/ readonly monitoredInstanceDisplayName!: pulumi.Output<string>;
    /**
     * OCID of monitored instance.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly monitoredInstanceId!: pulumi.Output<string>;
    public /*out*/ readonly monitoredInstanceManagementAgentId!: pulumi.Output<string>;
    public /*out*/ readonly state!: pulumi.Output<string>;

    /**
     * Create a MonitorPluginManagement resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: MonitorPluginManagementArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: MonitorPluginManagementArgs | MonitorPluginManagementState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as MonitorPluginManagementState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["monitoredInstanceDescription"] = state ? state.monitoredInstanceDescription : undefined;
            resourceInputs["monitoredInstanceDisplayName"] = state ? state.monitoredInstanceDisplayName : undefined;
            resourceInputs["monitoredInstanceId"] = state ? state.monitoredInstanceId : undefined;
            resourceInputs["monitoredInstanceManagementAgentId"] = state ? state.monitoredInstanceManagementAgentId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
        } else {
            const args = argsOrState as MonitorPluginManagementArgs | undefined;
            if ((!args || args.monitoredInstanceId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'monitoredInstanceId'");
            }
            resourceInputs["monitoredInstanceId"] = args ? args.monitoredInstanceId : undefined;
            resourceInputs["compartmentId"] = undefined /*out*/;
            resourceInputs["monitoredInstanceDescription"] = undefined /*out*/;
            resourceInputs["monitoredInstanceDisplayName"] = undefined /*out*/;
            resourceInputs["monitoredInstanceManagementAgentId"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(MonitorPluginManagement.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering MonitorPluginManagement resources.
 */
export interface MonitorPluginManagementState {
    compartmentId?: pulumi.Input<string>;
    monitoredInstanceDescription?: pulumi.Input<string>;
    monitoredInstanceDisplayName?: pulumi.Input<string>;
    /**
     * OCID of monitored instance.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    monitoredInstanceId?: pulumi.Input<string>;
    monitoredInstanceManagementAgentId?: pulumi.Input<string>;
    state?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a MonitorPluginManagement resource.
 */
export interface MonitorPluginManagementArgs {
    /**
     * OCID of monitored instance.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    monitoredInstanceId: pulumi.Input<string>;
}
