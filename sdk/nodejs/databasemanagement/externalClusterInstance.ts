// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the External Cluster Instance resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Updates the external cluster instance specified by `externalClusterInstanceId`.
 *
 * ## Import
 *
 * ExternalClusterInstances can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:DatabaseManagement/externalClusterInstance:ExternalClusterInstance test_external_cluster_instance "id"
 * ```
 */
export class ExternalClusterInstance extends pulumi.CustomResource {
    /**
     * Get an existing ExternalClusterInstance resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ExternalClusterInstanceState, opts?: pulumi.CustomResourceOptions): ExternalClusterInstance {
        return new ExternalClusterInstance(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DatabaseManagement/externalClusterInstance:ExternalClusterInstance';

    /**
     * Returns true if the given object is an instance of ExternalClusterInstance.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ExternalClusterInstance {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ExternalClusterInstance.__pulumiType;
    }

    /**
     * The Automatic Diagnostic Repository (ADR) home directory for the cluster instance.
     */
    public /*out*/ readonly adrHomeDirectory!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    public /*out*/ readonly compartmentId!: pulumi.Output<string>;
    /**
     * The name of the external cluster instance.
     */
    public /*out*/ readonly componentName!: pulumi.Output<string>;
    /**
     * The Oracle base location of Cluster Ready Services (CRS).
     */
    public /*out*/ readonly crsBaseDirectory!: pulumi.Output<string>;
    /**
     * The user-friendly name for the cluster instance. The name does not have to be unique.
     */
    public /*out*/ readonly displayName!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster that the cluster instance belongs to.
     */
    public /*out*/ readonly externalClusterId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster instance.
     */
    public readonly externalClusterInstanceId!: pulumi.Output<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
     */
    public readonly externalConnectorId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB node.
     */
    public /*out*/ readonly externalDbNodeId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the cluster instance is a part of.
     */
    public /*out*/ readonly externalDbSystemId!: pulumi.Output<string>;
    /**
     * The name of the host on which the cluster instance is running.
     */
    public /*out*/ readonly hostName!: pulumi.Output<string>;
    /**
     * Additional information about the current lifecycle state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * The role of the cluster node.
     */
    public /*out*/ readonly nodeRole!: pulumi.Output<string>;
    /**
     * The current lifecycle state of the external cluster instance.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the external cluster instance was created.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the external cluster instance was last updated.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a ExternalClusterInstance resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ExternalClusterInstanceArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ExternalClusterInstanceArgs | ExternalClusterInstanceState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ExternalClusterInstanceState | undefined;
            resourceInputs["adrHomeDirectory"] = state ? state.adrHomeDirectory : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["componentName"] = state ? state.componentName : undefined;
            resourceInputs["crsBaseDirectory"] = state ? state.crsBaseDirectory : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["externalClusterId"] = state ? state.externalClusterId : undefined;
            resourceInputs["externalClusterInstanceId"] = state ? state.externalClusterInstanceId : undefined;
            resourceInputs["externalConnectorId"] = state ? state.externalConnectorId : undefined;
            resourceInputs["externalDbNodeId"] = state ? state.externalDbNodeId : undefined;
            resourceInputs["externalDbSystemId"] = state ? state.externalDbSystemId : undefined;
            resourceInputs["hostName"] = state ? state.hostName : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["nodeRole"] = state ? state.nodeRole : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as ExternalClusterInstanceArgs | undefined;
            if ((!args || args.externalClusterInstanceId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'externalClusterInstanceId'");
            }
            resourceInputs["externalClusterInstanceId"] = args ? args.externalClusterInstanceId : undefined;
            resourceInputs["externalConnectorId"] = args ? args.externalConnectorId : undefined;
            resourceInputs["adrHomeDirectory"] = undefined /*out*/;
            resourceInputs["compartmentId"] = undefined /*out*/;
            resourceInputs["componentName"] = undefined /*out*/;
            resourceInputs["crsBaseDirectory"] = undefined /*out*/;
            resourceInputs["displayName"] = undefined /*out*/;
            resourceInputs["externalClusterId"] = undefined /*out*/;
            resourceInputs["externalDbNodeId"] = undefined /*out*/;
            resourceInputs["externalDbSystemId"] = undefined /*out*/;
            resourceInputs["hostName"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["nodeRole"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ExternalClusterInstance.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ExternalClusterInstance resources.
 */
export interface ExternalClusterInstanceState {
    /**
     * The Automatic Diagnostic Repository (ADR) home directory for the cluster instance.
     */
    adrHomeDirectory?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The name of the external cluster instance.
     */
    componentName?: pulumi.Input<string>;
    /**
     * The Oracle base location of Cluster Ready Services (CRS).
     */
    crsBaseDirectory?: pulumi.Input<string>;
    /**
     * The user-friendly name for the cluster instance. The name does not have to be unique.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster that the cluster instance belongs to.
     */
    externalClusterId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster instance.
     */
    externalClusterInstanceId?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
     */
    externalConnectorId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB node.
     */
    externalDbNodeId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the cluster instance is a part of.
     */
    externalDbSystemId?: pulumi.Input<string>;
    /**
     * The name of the host on which the cluster instance is running.
     */
    hostName?: pulumi.Input<string>;
    /**
     * Additional information about the current lifecycle state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The role of the cluster node.
     */
    nodeRole?: pulumi.Input<string>;
    /**
     * The current lifecycle state of the external cluster instance.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the external cluster instance was created.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the external cluster instance was last updated.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ExternalClusterInstance resource.
 */
export interface ExternalClusterInstanceArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster instance.
     */
    externalClusterInstanceId: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
     */
    externalConnectorId?: pulumi.Input<string>;
}