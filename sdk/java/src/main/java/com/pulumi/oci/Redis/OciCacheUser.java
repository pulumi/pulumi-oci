// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Redis;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Redis.OciCacheUserArgs;
import com.pulumi.oci.Redis.inputs.OciCacheUserState;
import com.pulumi.oci.Redis.outputs.OciCacheUserAuthenticationMode;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Oci Cache User resource in Oracle Cloud Infrastructure Redis service.
 * 
 * Creates a new Oracle Cloud Infrastructure Cache user. Oracle Cloud Infrastructure Cache user is required to authenticate to Oracle Cloud Infrastructure Cache cluster.
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
 * import com.pulumi.oci.Redis.OciCacheUser;
 * import com.pulumi.oci.Redis.OciCacheUserArgs;
 * import com.pulumi.oci.Redis.inputs.OciCacheUserAuthenticationModeArgs;
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
 *         var testOciCacheUser = new OciCacheUser("testOciCacheUser", OciCacheUserArgs.builder()
 *             .aclString(ociCacheUserAclString)
 *             .authenticationMode(OciCacheUserAuthenticationModeArgs.builder()
 *                 .authenticationType(ociCacheUserAuthenticationModeAuthenticationType)
 *                 .hashedPasswords(ociCacheUserAuthenticationModeHashedPasswords)
 *                 .build())
 *             .compartmentId(compartmentId)
 *             .description(ociCacheUserDescription)
 *             .name(ociCacheUserName)
 *             .definedTags(Map.of("foo-namespace.bar-key", "value"))
 *             .freeformTags(Map.of("bar-key", "value"))
 *             .status(ociCacheUserStatus)
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
 * OciCacheUsers can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:Redis/ociCacheUser:OciCacheUser test_oci_cache_user &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Redis/ociCacheUser:OciCacheUser")
public class OciCacheUser extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) ACL string of Oracle Cloud Infrastructure cache user.
     * 
     */
    @Export(name="aclString", refs={String.class}, tree="[0]")
    private Output<String> aclString;

    /**
     * @return (Updatable) ACL string of Oracle Cloud Infrastructure cache user.
     * 
     */
    public Output<String> aclString() {
        return this.aclString;
    }
    /**
     * (Updatable) These are the Authentication details of an Oracle Cloud Infrastructure cache user.
     * 
     */
    @Export(name="authenticationMode", refs={OciCacheUserAuthenticationMode.class}, tree="[0]")
    private Output<OciCacheUserAuthenticationMode> authenticationMode;

    /**
     * @return (Updatable) These are the Authentication details of an Oracle Cloud Infrastructure cache user.
     * 
     */
    public Output<OciCacheUserAuthenticationMode> authenticationMode() {
        return this.authenticationMode;
    }
    /**
     * (Updatable) Oracle Cloud Infrastructure cache user compartment ID.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) Oracle Cloud Infrastructure cache user compartment ID.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Description of Oracle Cloud Infrastructure cache user.
     * 
     */
    @Export(name="description", refs={String.class}, tree="[0]")
    private Output<String> description;

    /**
     * @return (Updatable) Description of Oracle Cloud Infrastructure cache user.
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * Oracle Cloud Infrastructure cache user name is required to connect to an Oracle Cloud Infrastructure cache cluster.
     * 
     */
    @Export(name="name", refs={String.class}, tree="[0]")
    private Output<String> name;

    /**
     * @return Oracle Cloud Infrastructure cache user name is required to connect to an Oracle Cloud Infrastructure cache cluster.
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * Oracle Cloud Infrastructure Cache user lifecycle state.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return Oracle Cloud Infrastructure Cache user lifecycle state.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * (Updatable) Oracle Cloud Infrastructure cache user status. ON enables and OFF disables the Oracle Cloud Infrastructure cache user to login to the associated clusters. Default value is ON.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="status", refs={String.class}, tree="[0]")
    private Output<String> status;

    /**
     * @return (Updatable) Oracle Cloud Infrastructure cache user status. ON enables and OFF disables the Oracle Cloud Infrastructure cache user to login to the associated clusters. Default value is ON.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> status() {
        return this.status;
    }
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,String>> systemTags() {
        return this.systemTags;
    }
    /**
     * The date and time, when the Oracle Cloud Infrastructure cache user was created.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The date and time, when the Oracle Cloud Infrastructure cache user was created.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The date and time, when the Oracle Cloud Infrastructure cache user was updated.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The date and time, when the Oracle Cloud Infrastructure cache user was updated.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public OciCacheUser(java.lang.String name) {
        this(name, OciCacheUserArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public OciCacheUser(java.lang.String name, OciCacheUserArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public OciCacheUser(java.lang.String name, OciCacheUserArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Redis/ociCacheUser:OciCacheUser", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private OciCacheUser(java.lang.String name, Output<java.lang.String> id, @Nullable OciCacheUserState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Redis/ociCacheUser:OciCacheUser", name, state, makeResourceOptions(options, id), false);
    }

    private static OciCacheUserArgs makeArgs(OciCacheUserArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? OciCacheUserArgs.Empty : args;
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
    public static OciCacheUser get(java.lang.String name, Output<java.lang.String> id, @Nullable OciCacheUserState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new OciCacheUser(name, id, state, options);
    }
}
