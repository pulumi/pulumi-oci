// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Oci Cache User Get Redis Cluster resource in Oracle Cloud Infrastructure Redis service.
 *
 * Gets a list of associated redis cluster for an Oracle Cloud Infrastructure cache user.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOciCacheUserGetRedisCluster = new oci.redis.OciCacheUserGetRedisCluster("test_oci_cache_user_get_redis_cluster", {
 *     ociCacheUserId: testOciCacheUser.id,
 *     compartmentId: compartmentId,
 *     displayName: ociCacheUserGetRedisClusterDisplayName,
 * });
 * ```
 *
 * ## Import
 *
 * Import is not supported for this resource.
 */
export class OciCacheUserGetRedisCluster extends pulumi.CustomResource {
    /**
     * Get an existing OciCacheUserGetRedisCluster resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: OciCacheUserGetRedisClusterState, opts?: pulumi.CustomResourceOptions): OciCacheUserGetRedisCluster {
        return new OciCacheUserGetRedisCluster(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Redis/ociCacheUserGetRedisCluster:OciCacheUserGetRedisCluster';

    /**
     * Returns true if the given object is an instance of OciCacheUserGetRedisCluster.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is OciCacheUserGetRedisCluster {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === OciCacheUserGetRedisCluster.__pulumiType;
    }

    /**
     * The ID of the compartment in which to list resources.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    public readonly displayName!: pulumi.Output<string>;
    public /*out*/ readonly ociCacheClusters!: pulumi.Output<outputs.Redis.OciCacheUserGetRedisClusterOciCacheCluster[]>;
    /**
     * A filter to return only resources, that match with the given Oracle Cloud Infrastructure cache user ID (OCID).
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly ociCacheUserId!: pulumi.Output<string>;

    /**
     * Create a OciCacheUserGetRedisCluster resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: OciCacheUserGetRedisClusterArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: OciCacheUserGetRedisClusterArgs | OciCacheUserGetRedisClusterState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as OciCacheUserGetRedisClusterState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["ociCacheClusters"] = state ? state.ociCacheClusters : undefined;
            resourceInputs["ociCacheUserId"] = state ? state.ociCacheUserId : undefined;
        } else {
            const args = argsOrState as OciCacheUserGetRedisClusterArgs | undefined;
            if ((!args || args.ociCacheUserId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'ociCacheUserId'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["ociCacheUserId"] = args ? args.ociCacheUserId : undefined;
            resourceInputs["ociCacheClusters"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(OciCacheUserGetRedisCluster.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering OciCacheUserGetRedisCluster resources.
 */
export interface OciCacheUserGetRedisClusterState {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: pulumi.Input<string>;
    ociCacheClusters?: pulumi.Input<pulumi.Input<inputs.Redis.OciCacheUserGetRedisClusterOciCacheCluster>[]>;
    /**
     * A filter to return only resources, that match with the given Oracle Cloud Infrastructure cache user ID (OCID).
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    ociCacheUserId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a OciCacheUserGetRedisCluster resource.
 */
export interface OciCacheUserGetRedisClusterArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: pulumi.Input<string>;
    /**
     * A filter to return only resources, that match with the given Oracle Cloud Infrastructure cache user ID (OCID).
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    ociCacheUserId: pulumi.Input<string>;
}
