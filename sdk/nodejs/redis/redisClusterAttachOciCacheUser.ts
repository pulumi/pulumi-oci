// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Redis Cluster Attach Oci Cache User resource in Oracle Cloud Infrastructure Redis service.
 *
 * Attach existing Oracle Cloud Infrastructure cache users to a redis cluster.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRedisClusterAttachOciCacheUser = new oci.redis.RedisClusterAttachOciCacheUser("test_redis_cluster_attach_oci_cache_user", {
 *     ociCacheUsers: redisClusterAttachOciCacheUserOciCacheUsers,
 *     redisClusterId: testRedisCluster.id,
 * });
 * ```
 *
 * ## Import
 *
 * Import is not supported for this resource.
 */
export class RedisClusterAttachOciCacheUser extends pulumi.CustomResource {
    /**
     * Get an existing RedisClusterAttachOciCacheUser resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: RedisClusterAttachOciCacheUserState, opts?: pulumi.CustomResourceOptions): RedisClusterAttachOciCacheUser {
        return new RedisClusterAttachOciCacheUser(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Redis/redisClusterAttachOciCacheUser:RedisClusterAttachOciCacheUser';

    /**
     * Returns true if the given object is an instance of RedisClusterAttachOciCacheUser.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is RedisClusterAttachOciCacheUser {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === RedisClusterAttachOciCacheUser.__pulumiType;
    }

    /**
     * List of Oracle Cloud Infrastructure cache user unique IDs (OCIDs).
     */
    public readonly ociCacheUsers!: pulumi.Output<string[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly redisClusterId!: pulumi.Output<string>;

    /**
     * Create a RedisClusterAttachOciCacheUser resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: RedisClusterAttachOciCacheUserArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: RedisClusterAttachOciCacheUserArgs | RedisClusterAttachOciCacheUserState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as RedisClusterAttachOciCacheUserState | undefined;
            resourceInputs["ociCacheUsers"] = state ? state.ociCacheUsers : undefined;
            resourceInputs["redisClusterId"] = state ? state.redisClusterId : undefined;
        } else {
            const args = argsOrState as RedisClusterAttachOciCacheUserArgs | undefined;
            if ((!args || args.ociCacheUsers === undefined) && !opts.urn) {
                throw new Error("Missing required property 'ociCacheUsers'");
            }
            if ((!args || args.redisClusterId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'redisClusterId'");
            }
            resourceInputs["ociCacheUsers"] = args ? args.ociCacheUsers : undefined;
            resourceInputs["redisClusterId"] = args ? args.redisClusterId : undefined;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(RedisClusterAttachOciCacheUser.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering RedisClusterAttachOciCacheUser resources.
 */
export interface RedisClusterAttachOciCacheUserState {
    /**
     * List of Oracle Cloud Infrastructure cache user unique IDs (OCIDs).
     */
    ociCacheUsers?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    redisClusterId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a RedisClusterAttachOciCacheUser resource.
 */
export interface RedisClusterAttachOciCacheUserArgs {
    /**
     * List of Oracle Cloud Infrastructure cache user unique IDs (OCIDs).
     */
    ociCacheUsers: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    redisClusterId: pulumi.Input<string>;
}
