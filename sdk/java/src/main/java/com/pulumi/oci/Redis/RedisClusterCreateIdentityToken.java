// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Redis;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Redis.RedisClusterCreateIdentityTokenArgs;
import com.pulumi.oci.Redis.inputs.RedisClusterCreateIdentityTokenState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Redis Cluster Create Identity Token resource in Oracle Cloud Infrastructure Redis service.
 * 
 * Generates an identity token to sign in with the specified redis user for the redis cluster
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
 * import com.pulumi.oci.Redis.RedisClusterCreateIdentityToken;
 * import com.pulumi.oci.Redis.RedisClusterCreateIdentityTokenArgs;
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
 *         var testRedisClusterCreateIdentityToken = new RedisClusterCreateIdentityToken("testRedisClusterCreateIdentityToken", RedisClusterCreateIdentityTokenArgs.builder()
 *             .publicKey(redisClusterCreateIdentityTokenPublicKey)
 *             .redisClusterId(testRedisCluster.id())
 *             .redisUser(redisClusterCreateIdentityTokenRedisUser)
 *             .definedTags(redisClusterCreateIdentityTokenDefinedTags)
 *             .freeformTags(redisClusterCreateIdentityTokenFreeformTags)
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
@ResourceType(type="oci:Redis/redisClusterCreateIdentityToken:RedisClusterCreateIdentityToken")
public class RedisClusterCreateIdentityToken extends com.pulumi.resources.CustomResource {
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output</* @Nullable */ Map<String,String>> definedTags;

    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Optional<Map<String,String>>> definedTags() {
        return Codegen.optional(this.definedTags);
    }
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output</* @Nullable */ Map<String,String>> freeformTags;

    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Optional<Map<String,String>>> freeformTags() {
        return Codegen.optional(this.freeformTags);
    }
    /**
     * Generated Identity token
     * 
     */
    @Export(name="identityToken", refs={String.class}, tree="[0]")
    private Output<String> identityToken;

    /**
     * @return Generated Identity token
     * 
     */
    public Output<String> identityToken() {
        return this.identityToken;
    }
    /**
     * User public key pair
     * 
     */
    @Export(name="publicKey", refs={String.class}, tree="[0]")
    private Output<String> publicKey;

    /**
     * @return User public key pair
     * 
     */
    public Output<String> publicKey() {
        return this.publicKey;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.
     * 
     */
    @Export(name="redisClusterId", refs={String.class}, tree="[0]")
    private Output<String> redisClusterId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.
     * 
     */
    public Output<String> redisClusterId() {
        return this.redisClusterId;
    }
    /**
     * Redis User generating identity token.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="redisUser", refs={String.class}, tree="[0]")
    private Output<String> redisUser;

    /**
     * @return Redis User generating identity token.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> redisUser() {
        return this.redisUser;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public RedisClusterCreateIdentityToken(java.lang.String name) {
        this(name, RedisClusterCreateIdentityTokenArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public RedisClusterCreateIdentityToken(java.lang.String name, RedisClusterCreateIdentityTokenArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public RedisClusterCreateIdentityToken(java.lang.String name, RedisClusterCreateIdentityTokenArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Redis/redisClusterCreateIdentityToken:RedisClusterCreateIdentityToken", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private RedisClusterCreateIdentityToken(java.lang.String name, Output<java.lang.String> id, @Nullable RedisClusterCreateIdentityTokenState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Redis/redisClusterCreateIdentityToken:RedisClusterCreateIdentityToken", name, state, makeResourceOptions(options, id), false);
    }

    private static RedisClusterCreateIdentityTokenArgs makeArgs(RedisClusterCreateIdentityTokenArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? RedisClusterCreateIdentityTokenArgs.Empty : args;
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
    public static RedisClusterCreateIdentityToken get(java.lang.String name, Output<java.lang.String> id, @Nullable RedisClusterCreateIdentityTokenState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new RedisClusterCreateIdentityToken(name, id, state, options);
    }
}
