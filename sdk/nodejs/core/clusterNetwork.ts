// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Cluster Network resource in Oracle Cloud Infrastructure Core service.
 *
 * Creates a [cluster network with instance pools](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/managingclusternetworks.htm).
 * A cluster network is a group of high performance computing (HPC), GPU, or optimized bare metal
 * instances that are connected with an ultra low-latency remote direct memory access (RDMA) network.
 * Cluster networks with instance pools use instance pools to manage groups of identical instances.
 *
 * Use cluster networks with instance pools when you want predictable capacity for a specific number of identical
 * instances that are managed as a group.
 *
 * If you want to manage instances in the RDMA network independently of each other or use different types of instances
 * in the network group, create a compute cluster by using the [CreateComputeCluster](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ComputeCluster/CreateComputeCluster)
 * operation.
 *
 * To determine whether capacity is available for a specific shape before you create a cluster network,
 * use the [CreateComputeCapacityReport](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ComputeCapacityReport/CreateComputeCapacityReport)
 * operation.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testClusterNetwork = new oci.core.ClusterNetwork("test_cluster_network", {
 *     compartmentId: compartmentId,
 *     instancePools: [{
 *         instanceConfigurationId: testInstanceConfiguration.id,
 *         size: clusterNetworkInstancePoolsSize,
 *         definedTags: {
 *             "Operations.CostCenter": "42",
 *         },
 *         displayName: clusterNetworkInstancePoolsDisplayName,
 *         freeformTags: {
 *             Department: "Finance",
 *         },
 *     }],
 *     placementConfiguration: {
 *         availabilityDomain: clusterNetworkPlacementConfigurationAvailabilityDomain,
 *         primaryVnicSubnets: {
 *             subnetId: testSubnet.id,
 *             ipv6addressIpv6subnetCidrPairDetails: [{
 *                 ipv6subnetCidr: clusterNetworkPlacementConfigurationPrimaryVnicSubnetsIpv6addressIpv6subnetCidrPairDetailsIpv6subnetCidr,
 *             }],
 *             isAssignIpv6ip: clusterNetworkPlacementConfigurationPrimaryVnicSubnetsIsAssignIpv6ip,
 *         },
 *         secondaryVnicSubnets: [{
 *             subnetId: testSubnet.id,
 *             displayName: clusterNetworkPlacementConfigurationSecondaryVnicSubnetsDisplayName,
 *             ipv6addressIpv6subnetCidrPairDetails: [{
 *                 ipv6subnetCidr: clusterNetworkPlacementConfigurationSecondaryVnicSubnetsIpv6addressIpv6subnetCidrPairDetailsIpv6subnetCidr,
 *             }],
 *             isAssignIpv6ip: clusterNetworkPlacementConfigurationSecondaryVnicSubnetsIsAssignIpv6ip,
 *         }],
 *     },
 *     clusterConfiguration: {
 *         hpcIslandId: testHpcIsland.id,
 *         networkBlockIds: clusterNetworkClusterConfigurationNetworkBlockIds,
 *     },
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     displayName: clusterNetworkDisplayName,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * ClusterNetworks can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Core/clusterNetwork:ClusterNetwork test_cluster_network "id"
 * ```
 */
export class ClusterNetwork extends pulumi.CustomResource {
    /**
     * Get an existing ClusterNetwork resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ClusterNetworkState, opts?: pulumi.CustomResourceOptions): ClusterNetwork {
        return new ClusterNetwork(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Core/clusterNetwork:ClusterNetwork';

    /**
     * Returns true if the given object is an instance of ClusterNetwork.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ClusterNetwork {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ClusterNetwork.__pulumiType;
    }

    /**
     * The HPC cluster configuration requested when launching instances of a cluster network.
     *
     * If the parameter is provided, instances will only be placed within the HPC island and list of network blocks that you specify. If a list of network blocks are missing or not provided, the instances will be placed in any HPC blocks in the HPC island that you specify. If the values of HPC island or network block that you provide are not valid, an error is returned.
     */
    public readonly clusterConfiguration!: pulumi.Output<outputs.Core.ClusterNetworkClusterConfiguration>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the cluster network.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the HPC island used by the cluster network.
     */
    public /*out*/ readonly hpcIslandId!: pulumi.Output<string>;
    /**
     * (Updatable) The data to create the instance pools in the cluster network.
     *
     * Each cluster network can have one instance pool.
     */
    public readonly instancePools!: pulumi.Output<outputs.Core.ClusterNetworkInstancePool[]>;
    /**
     * The list of network block OCIDs of the HPC island.
     */
    public /*out*/ readonly networkBlockIds!: pulumi.Output<string[]>;
    /**
     * The location for where the instance pools in a cluster network will place instances.
     */
    public readonly placementConfiguration!: pulumi.Output<outputs.Core.ClusterNetworkPlacementConfiguration>;
    /**
     * The current state of the cluster network.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the resource was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a ClusterNetwork resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ClusterNetworkArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ClusterNetworkArgs | ClusterNetworkState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ClusterNetworkState | undefined;
            resourceInputs["clusterConfiguration"] = state ? state.clusterConfiguration : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["hpcIslandId"] = state ? state.hpcIslandId : undefined;
            resourceInputs["instancePools"] = state ? state.instancePools : undefined;
            resourceInputs["networkBlockIds"] = state ? state.networkBlockIds : undefined;
            resourceInputs["placementConfiguration"] = state ? state.placementConfiguration : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as ClusterNetworkArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.instancePools === undefined) && !opts.urn) {
                throw new Error("Missing required property 'instancePools'");
            }
            if ((!args || args.placementConfiguration === undefined) && !opts.urn) {
                throw new Error("Missing required property 'placementConfiguration'");
            }
            resourceInputs["clusterConfiguration"] = args ? args.clusterConfiguration : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["instancePools"] = args ? args.instancePools : undefined;
            resourceInputs["placementConfiguration"] = args ? args.placementConfiguration : undefined;
            resourceInputs["hpcIslandId"] = undefined /*out*/;
            resourceInputs["networkBlockIds"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ClusterNetwork.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ClusterNetwork resources.
 */
export interface ClusterNetworkState {
    /**
     * The HPC cluster configuration requested when launching instances of a cluster network.
     *
     * If the parameter is provided, instances will only be placed within the HPC island and list of network blocks that you specify. If a list of network blocks are missing or not provided, the instances will be placed in any HPC blocks in the HPC island that you specify. If the values of HPC island or network block that you provide are not valid, an error is returned.
     */
    clusterConfiguration?: pulumi.Input<inputs.Core.ClusterNetworkClusterConfiguration>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the cluster network.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the HPC island used by the cluster network.
     */
    hpcIslandId?: pulumi.Input<string>;
    /**
     * (Updatable) The data to create the instance pools in the cluster network.
     *
     * Each cluster network can have one instance pool.
     */
    instancePools?: pulumi.Input<pulumi.Input<inputs.Core.ClusterNetworkInstancePool>[]>;
    /**
     * The list of network block OCIDs of the HPC island.
     */
    networkBlockIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The location for where the instance pools in a cluster network will place instances.
     */
    placementConfiguration?: pulumi.Input<inputs.Core.ClusterNetworkPlacementConfiguration>;
    /**
     * The current state of the cluster network.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the resource was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ClusterNetwork resource.
 */
export interface ClusterNetworkArgs {
    /**
     * The HPC cluster configuration requested when launching instances of a cluster network.
     *
     * If the parameter is provided, instances will only be placed within the HPC island and list of network blocks that you specify. If a list of network blocks are missing or not provided, the instances will be placed in any HPC blocks in the HPC island that you specify. If the values of HPC island or network block that you provide are not valid, an error is returned.
     */
    clusterConfiguration?: pulumi.Input<inputs.Core.ClusterNetworkClusterConfiguration>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the cluster network.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The data to create the instance pools in the cluster network.
     *
     * Each cluster network can have one instance pool.
     */
    instancePools: pulumi.Input<pulumi.Input<inputs.Core.ClusterNetworkInstancePool>[]>;
    /**
     * The location for where the instance pools in a cluster network will place instances.
     */
    placementConfiguration: pulumi.Input<inputs.Core.ClusterNetworkPlacementConfiguration>;
}
