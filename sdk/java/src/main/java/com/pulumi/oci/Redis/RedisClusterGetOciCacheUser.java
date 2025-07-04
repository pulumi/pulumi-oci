// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Redis;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Redis.RedisClusterGetOciCacheUserArgs;
import com.pulumi.oci.Redis.inputs.RedisClusterGetOciCacheUserState;
import com.pulumi.oci.Redis.outputs.RedisClusterGetOciCacheUserOciCacheUser;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import javax.annotation.Nullable;

/**
 * This resource provides the Redis Cluster Get Oci Cache User resource in Oracle Cloud Infrastructure Redis service.
 * 
 * Gets a list of associated Oracle Cloud Infrastructure cache users for a redis cluster.
 * 
 * ## Example Usage
 * 
 * &lt;!--Start PulumiCodeChooser --&gt;
 * <pre>
 * {@code
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.Redis.RedisClusterGetOciCacheUser;
 * import com.pulumi.oci.Redis.RedisClusterGetOciCacheUserArgs;
 * import java.util.List;
 * import java.util.ArrayList;
 * import java.util.Map;
 * import java.io.File;
 * import java.nio.file.Files;
 * import java.nio.file.Paths;
 * 
 * public class App {
 *     public static void main(String[] args) {
 *         Pulumi.run(App::stack);
 *     }
 * 
 *     public static void stack(Context ctx) {
 *         var testRedisClusterGetOciCacheUser = new RedisClusterGetOciCacheUser("testRedisClusterGetOciCacheUser", RedisClusterGetOciCacheUserArgs.builder()
 *             .redisClusterId(testRedisCluster.id())
 *             .compartmentId(compartmentId)
 *             .displayName(redisClusterGetOciCacheUserDisplayName)
 *             .build());
 * 
 *     }
 * }
 * }
 * </pre>
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 * ## Import
 * 
 * Import is not supported for this resource.
 * 
 */
@ResourceType(type="oci:Redis/redisClusterGetOciCacheUser:RedisClusterGetOciCacheUser")
public class RedisClusterGetOciCacheUser extends com.pulumi.resources.CustomResource {
    /**
     * The ID of the compartment in which to list resources.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * A filter to return only resources that match the entire display name given.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    @Export(name="ociCacheUsers", refs={List.class,RedisClusterGetOciCacheUserOciCacheUser.class}, tree="[0,1]")
    private Output<List<RedisClusterGetOciCacheUserOciCacheUser>> ociCacheUsers;

    public Output<List<RedisClusterGetOciCacheUserOciCacheUser>> ociCacheUsers() {
        return this.ociCacheUsers;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="redisClusterId", refs={String.class}, tree="[0]")
    private Output<String> redisClusterId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> redisClusterId() {
        return this.redisClusterId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public RedisClusterGetOciCacheUser(java.lang.String name) {
        this(name, RedisClusterGetOciCacheUserArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public RedisClusterGetOciCacheUser(java.lang.String name, RedisClusterGetOciCacheUserArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public RedisClusterGetOciCacheUser(java.lang.String name, RedisClusterGetOciCacheUserArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Redis/redisClusterGetOciCacheUser:RedisClusterGetOciCacheUser", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private RedisClusterGetOciCacheUser(java.lang.String name, Output<java.lang.String> id, @Nullable RedisClusterGetOciCacheUserState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Redis/redisClusterGetOciCacheUser:RedisClusterGetOciCacheUser", name, state, makeResourceOptions(options, id), false);
    }

    private static RedisClusterGetOciCacheUserArgs makeArgs(RedisClusterGetOciCacheUserArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? RedisClusterGetOciCacheUserArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static RedisClusterGetOciCacheUser get(java.lang.String name, Output<java.lang.String> id, @Nullable RedisClusterGetOciCacheUserState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new RedisClusterGetOciCacheUser(name, id, state, options);
    }
}
