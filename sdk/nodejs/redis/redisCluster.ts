// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Redis Cluster resource in Oracle Cloud Infrastructure Redis service.
 *
 * Creates a new Redis cluster. A Redis cluster is a memory-based storage solution. For more information, see [OCI Caching Service with Redis](https://docs.cloud.oracle.com/iaas/Content/redis/home.htm).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRedisCluster = new oci.redis.RedisCluster("testRedisCluster", {
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.redis_cluster_display_name,
 *     nodeCount: _var.redis_cluster_node_count,
 *     nodeMemoryInGbs: _var.redis_cluster_node_memory_in_gbs,
 *     softwareVersion: _var.redis_cluster_software_version,
 *     subnetId: oci_core_subnet.test_subnet.id,
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * RedisClusters can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:Redis/redisCluster:RedisCluster test_redis_cluster "id"
 * ```
 */
export class RedisCluster extends pulumi.CustomResource {
    /**
     * Get an existing RedisCluster resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: RedisClusterState, opts?: pulumi.CustomResourceOptions): RedisCluster {
        return new RedisCluster(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Redis/redisCluster:RedisCluster';

    /**
     * Returns true if the given object is an instance of RedisCluster.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is RedisCluster {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === RedisCluster.__pulumiType;
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the compartment that contains the Redis cluster.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * A message describing the current state in more detail. For example, the message might provide actionable information for a resource in `FAILED` state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * The collection of Redis cluster nodes.
     */
    public /*out*/ readonly nodeCollections!: pulumi.Output<outputs.Redis.RedisClusterNodeCollection[]>;
    /**
     * (Updatable) The number of nodes in the Redis cluster.
     */
    public readonly nodeCount!: pulumi.Output<number>;
    /**
     * (Updatable) The amount of memory allocated to the Redis cluster's nodes, in gigabytes.
     */
    public readonly nodeMemoryInGbs!: pulumi.Output<number>;
    /**
     * The private IP address of the API endpoint for the Redis cluster's primary node.
     */
    public /*out*/ readonly primaryEndpointIpAddress!: pulumi.Output<string>;
    /**
     * The fully qualified domain name (FQDN) of the API endpoint for the Redis cluster's primary node.
     */
    public /*out*/ readonly primaryFqdn!: pulumi.Output<string>;
    /**
     * The private IP address of the API endpoint for the Redis cluster's replica nodes.
     */
    public /*out*/ readonly replicasEndpointIpAddress!: pulumi.Output<string>;
    /**
     * The fully qualified domain name (FQDN) of the API endpoint for the Redis cluster's replica nodes.
     */
    public /*out*/ readonly replicasFqdn!: pulumi.Output<string>;
    /**
     * The Redis version that the cluster is running.
     */
    public readonly softwareVersion!: pulumi.Output<string>;
    /**
     * The current state of the Redis cluster.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the Redis cluster's subnet.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly subnetId!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The date and time the Redis cluster was created. An [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the Redis cluster was updated. An [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a RedisCluster resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: RedisClusterArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: RedisClusterArgs | RedisClusterState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as RedisClusterState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["nodeCollections"] = state ? state.nodeCollections : undefined;
            resourceInputs["nodeCount"] = state ? state.nodeCount : undefined;
            resourceInputs["nodeMemoryInGbs"] = state ? state.nodeMemoryInGbs : undefined;
            resourceInputs["primaryEndpointIpAddress"] = state ? state.primaryEndpointIpAddress : undefined;
            resourceInputs["primaryFqdn"] = state ? state.primaryFqdn : undefined;
            resourceInputs["replicasEndpointIpAddress"] = state ? state.replicasEndpointIpAddress : undefined;
            resourceInputs["replicasFqdn"] = state ? state.replicasFqdn : undefined;
            resourceInputs["softwareVersion"] = state ? state.softwareVersion : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["subnetId"] = state ? state.subnetId : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as RedisClusterArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.nodeCount === undefined) && !opts.urn) {
                throw new Error("Missing required property 'nodeCount'");
            }
            if ((!args || args.nodeMemoryInGbs === undefined) && !opts.urn) {
                throw new Error("Missing required property 'nodeMemoryInGbs'");
            }
            if ((!args || args.softwareVersion === undefined) && !opts.urn) {
                throw new Error("Missing required property 'softwareVersion'");
            }
            if ((!args || args.subnetId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'subnetId'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["nodeCount"] = args ? args.nodeCount : undefined;
            resourceInputs["nodeMemoryInGbs"] = args ? args.nodeMemoryInGbs : undefined;
            resourceInputs["softwareVersion"] = args ? args.softwareVersion : undefined;
            resourceInputs["subnetId"] = args ? args.subnetId : undefined;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["nodeCollections"] = undefined /*out*/;
            resourceInputs["primaryEndpointIpAddress"] = undefined /*out*/;
            resourceInputs["primaryFqdn"] = undefined /*out*/;
            resourceInputs["replicasEndpointIpAddress"] = undefined /*out*/;
            resourceInputs["replicasFqdn"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(RedisCluster.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering RedisCluster resources.
 */
export interface RedisClusterState {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the compartment that contains the Redis cluster.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * A message describing the current state in more detail. For example, the message might provide actionable information for a resource in `FAILED` state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The collection of Redis cluster nodes.
     */
    nodeCollections?: pulumi.Input<pulumi.Input<inputs.Redis.RedisClusterNodeCollection>[]>;
    /**
     * (Updatable) The number of nodes in the Redis cluster.
     */
    nodeCount?: pulumi.Input<number>;
    /**
     * (Updatable) The amount of memory allocated to the Redis cluster's nodes, in gigabytes.
     */
    nodeMemoryInGbs?: pulumi.Input<number>;
    /**
     * The private IP address of the API endpoint for the Redis cluster's primary node.
     */
    primaryEndpointIpAddress?: pulumi.Input<string>;
    /**
     * The fully qualified domain name (FQDN) of the API endpoint for the Redis cluster's primary node.
     */
    primaryFqdn?: pulumi.Input<string>;
    /**
     * The private IP address of the API endpoint for the Redis cluster's replica nodes.
     */
    replicasEndpointIpAddress?: pulumi.Input<string>;
    /**
     * The fully qualified domain name (FQDN) of the API endpoint for the Redis cluster's replica nodes.
     */
    replicasFqdn?: pulumi.Input<string>;
    /**
     * The Redis version that the cluster is running.
     */
    softwareVersion?: pulumi.Input<string>;
    /**
     * The current state of the Redis cluster.
     */
    state?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the Redis cluster's subnet.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    subnetId?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The date and time the Redis cluster was created. An [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the Redis cluster was updated. An [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a RedisCluster resource.
 */
export interface RedisClusterArgs {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the compartment that contains the Redis cluster.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The number of nodes in the Redis cluster.
     */
    nodeCount: pulumi.Input<number>;
    /**
     * (Updatable) The amount of memory allocated to the Redis cluster's nodes, in gigabytes.
     */
    nodeMemoryInGbs: pulumi.Input<number>;
    /**
     * The Redis version that the cluster is running.
     */
    softwareVersion: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the Redis cluster's subnet.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    subnetId: pulumi.Input<string>;
}