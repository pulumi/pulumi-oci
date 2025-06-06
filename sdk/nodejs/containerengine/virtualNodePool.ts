// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Virtual Node Pool resource in Oracle Cloud Infrastructure Container Engine service.
 *
 * Create a new virtual node pool.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVirtualNodePool = new oci.containerengine.VirtualNodePool("test_virtual_node_pool", {
 *     clusterId: testCluster.id,
 *     compartmentId: compartmentId,
 *     displayName: virtualNodePoolDisplayName,
 *     placementConfigurations: [{
 *         availabilityDomain: virtualNodePoolPlacementConfigurationsAvailabilityDomain,
 *         faultDomains: virtualNodePoolPlacementConfigurationsFaultDomain,
 *         subnetId: testSubnet.id,
 *     }],
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     initialVirtualNodeLabels: [{
 *         key: virtualNodePoolInitialVirtualNodeLabelsKey,
 *         value: virtualNodePoolInitialVirtualNodeLabelsValue,
 *     }],
 *     nsgIds: virtualNodePoolNsgIds,
 *     podConfiguration: {
 *         shape: virtualNodePoolPodConfigurationShape,
 *         subnetId: testSubnet.id,
 *         nsgIds: virtualNodePoolPodConfigurationNsgIds,
 *     },
 *     size: virtualNodePoolSize,
 *     taints: [{
 *         effect: virtualNodePoolTaintsEffect,
 *         key: virtualNodePoolTaintsKey,
 *         value: virtualNodePoolTaintsValue,
 *     }],
 *     virtualNodeTags: {
 *         definedTags: {
 *             "Operations.CostCenter": "42",
 *         },
 *         freeformTags: {
 *             Department: "Finance",
 *         },
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * VirtualNodePools can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:ContainerEngine/virtualNodePool:VirtualNodePool test_virtual_node_pool "id"
 * ```
 */
export class VirtualNodePool extends pulumi.CustomResource {
    /**
     * Get an existing VirtualNodePool resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: VirtualNodePoolState, opts?: pulumi.CustomResourceOptions): VirtualNodePool {
        return new VirtualNodePool(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:ContainerEngine/virtualNodePool:VirtualNodePool';

    /**
     * Returns true if the given object is an instance of VirtualNodePool.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is VirtualNodePool {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === VirtualNodePool.__pulumiType;
    }

    /**
     * The cluster the virtual node pool is associated with. A virtual node pool can only be associated with one cluster.
     */
    public readonly clusterId!: pulumi.Output<string>;
    /**
     * Compartment of the virtual node pool.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Display name of the virtual node pool. This is a non-unique value.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Initial labels that will be added to the Kubernetes Virtual Node object when it registers.
     */
    public readonly initialVirtualNodeLabels!: pulumi.Output<outputs.ContainerEngine.VirtualNodePoolInitialVirtualNodeLabel[]>;
    /**
     * The version of Kubernetes running on the nodes in the node pool.
     */
    public /*out*/ readonly kubernetesVersion!: pulumi.Output<string>;
    /**
     * Details about the state of the Virtual Node Pool.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * (Updatable) List of network security group id's applied to the Virtual Node VNIC.
     */
    public readonly nsgIds!: pulumi.Output<string[]>;
    /**
     * (Updatable) The list of placement configurations which determines where Virtual Nodes will be provisioned across as it relates to the subnet and availability domains. The size attribute determines how many we evenly spread across these placement configurations
     */
    public readonly placementConfigurations!: pulumi.Output<outputs.ContainerEngine.VirtualNodePoolPlacementConfiguration[]>;
    /**
     * (Updatable) The pod configuration for pods run on virtual nodes of this virtual node pool.
     */
    public readonly podConfiguration!: pulumi.Output<outputs.ContainerEngine.VirtualNodePoolPodConfiguration>;
    /**
     * (Updatable) The number of Virtual Nodes that should be in the Virtual Node Pool. The placement configurations determine where these virtual nodes are placed.
     */
    public readonly size!: pulumi.Output<number>;
    /**
     * The state of the Virtual Node Pool.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) A taint is a collection of <key, value, effect>. These taints will be applied to the Virtual Nodes of this Virtual Node Pool for Kubernetes scheduling.
     */
    public readonly taints!: pulumi.Output<outputs.ContainerEngine.VirtualNodePoolTaint[]>;
    /**
     * The time the virtual node pool was created.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time the virtual node pool was updated.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * (Updatable) The tags associated to the virtual nodes in this virtual node pool.
     */
    public readonly virtualNodeTags!: pulumi.Output<outputs.ContainerEngine.VirtualNodePoolVirtualNodeTags>;

    /**
     * Create a VirtualNodePool resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: VirtualNodePoolArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: VirtualNodePoolArgs | VirtualNodePoolState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as VirtualNodePoolState | undefined;
            resourceInputs["clusterId"] = state ? state.clusterId : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["initialVirtualNodeLabels"] = state ? state.initialVirtualNodeLabels : undefined;
            resourceInputs["kubernetesVersion"] = state ? state.kubernetesVersion : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["nsgIds"] = state ? state.nsgIds : undefined;
            resourceInputs["placementConfigurations"] = state ? state.placementConfigurations : undefined;
            resourceInputs["podConfiguration"] = state ? state.podConfiguration : undefined;
            resourceInputs["size"] = state ? state.size : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["taints"] = state ? state.taints : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["virtualNodeTags"] = state ? state.virtualNodeTags : undefined;
        } else {
            const args = argsOrState as VirtualNodePoolArgs | undefined;
            if ((!args || args.clusterId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'clusterId'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.placementConfigurations === undefined) && !opts.urn) {
                throw new Error("Missing required property 'placementConfigurations'");
            }
            if ((!args || args.podConfiguration === undefined) && !opts.urn) {
                throw new Error("Missing required property 'podConfiguration'");
            }
            if ((!args || args.size === undefined) && !opts.urn) {
                throw new Error("Missing required property 'size'");
            }
            resourceInputs["clusterId"] = args ? args.clusterId : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["initialVirtualNodeLabels"] = args ? args.initialVirtualNodeLabels : undefined;
            resourceInputs["nsgIds"] = args ? args.nsgIds : undefined;
            resourceInputs["placementConfigurations"] = args ? args.placementConfigurations : undefined;
            resourceInputs["podConfiguration"] = args ? args.podConfiguration : undefined;
            resourceInputs["size"] = args ? args.size : undefined;
            resourceInputs["taints"] = args ? args.taints : undefined;
            resourceInputs["virtualNodeTags"] = args ? args.virtualNodeTags : undefined;
            resourceInputs["kubernetesVersion"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(VirtualNodePool.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering VirtualNodePool resources.
 */
export interface VirtualNodePoolState {
    /**
     * The cluster the virtual node pool is associated with. A virtual node pool can only be associated with one cluster.
     */
    clusterId?: pulumi.Input<string>;
    /**
     * Compartment of the virtual node pool.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Display name of the virtual node pool. This is a non-unique value.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Initial labels that will be added to the Kubernetes Virtual Node object when it registers.
     */
    initialVirtualNodeLabels?: pulumi.Input<pulumi.Input<inputs.ContainerEngine.VirtualNodePoolInitialVirtualNodeLabel>[]>;
    /**
     * The version of Kubernetes running on the nodes in the node pool.
     */
    kubernetesVersion?: pulumi.Input<string>;
    /**
     * Details about the state of the Virtual Node Pool.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * (Updatable) List of network security group id's applied to the Virtual Node VNIC.
     */
    nsgIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) The list of placement configurations which determines where Virtual Nodes will be provisioned across as it relates to the subnet and availability domains. The size attribute determines how many we evenly spread across these placement configurations
     */
    placementConfigurations?: pulumi.Input<pulumi.Input<inputs.ContainerEngine.VirtualNodePoolPlacementConfiguration>[]>;
    /**
     * (Updatable) The pod configuration for pods run on virtual nodes of this virtual node pool.
     */
    podConfiguration?: pulumi.Input<inputs.ContainerEngine.VirtualNodePoolPodConfiguration>;
    /**
     * (Updatable) The number of Virtual Nodes that should be in the Virtual Node Pool. The placement configurations determine where these virtual nodes are placed.
     */
    size?: pulumi.Input<number>;
    /**
     * The state of the Virtual Node Pool.
     */
    state?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A taint is a collection of <key, value, effect>. These taints will be applied to the Virtual Nodes of this Virtual Node Pool for Kubernetes scheduling.
     */
    taints?: pulumi.Input<pulumi.Input<inputs.ContainerEngine.VirtualNodePoolTaint>[]>;
    /**
     * The time the virtual node pool was created.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time the virtual node pool was updated.
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * (Updatable) The tags associated to the virtual nodes in this virtual node pool.
     */
    virtualNodeTags?: pulumi.Input<inputs.ContainerEngine.VirtualNodePoolVirtualNodeTags>;
}

/**
 * The set of arguments for constructing a VirtualNodePool resource.
 */
export interface VirtualNodePoolArgs {
    /**
     * The cluster the virtual node pool is associated with. A virtual node pool can only be associated with one cluster.
     */
    clusterId: pulumi.Input<string>;
    /**
     * Compartment of the virtual node pool.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Display name of the virtual node pool. This is a non-unique value.
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Initial labels that will be added to the Kubernetes Virtual Node object when it registers.
     */
    initialVirtualNodeLabels?: pulumi.Input<pulumi.Input<inputs.ContainerEngine.VirtualNodePoolInitialVirtualNodeLabel>[]>;
    /**
     * (Updatable) List of network security group id's applied to the Virtual Node VNIC.
     */
    nsgIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) The list of placement configurations which determines where Virtual Nodes will be provisioned across as it relates to the subnet and availability domains. The size attribute determines how many we evenly spread across these placement configurations
     */
    placementConfigurations: pulumi.Input<pulumi.Input<inputs.ContainerEngine.VirtualNodePoolPlacementConfiguration>[]>;
    /**
     * (Updatable) The pod configuration for pods run on virtual nodes of this virtual node pool.
     */
    podConfiguration: pulumi.Input<inputs.ContainerEngine.VirtualNodePoolPodConfiguration>;
    /**
     * (Updatable) The number of Virtual Nodes that should be in the Virtual Node Pool. The placement configurations determine where these virtual nodes are placed.
     */
    size: pulumi.Input<number>;
    /**
     * (Updatable) A taint is a collection of <key, value, effect>. These taints will be applied to the Virtual Nodes of this Virtual Node Pool for Kubernetes scheduling.
     */
    taints?: pulumi.Input<pulumi.Input<inputs.ContainerEngine.VirtualNodePoolTaint>[]>;
    /**
     * (Updatable) The tags associated to the virtual nodes in this virtual node pool.
     */
    virtualNodeTags?: pulumi.Input<inputs.ContainerEngine.VirtualNodePoolVirtualNodeTags>;
}
