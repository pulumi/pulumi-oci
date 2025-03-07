// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Dns.TsigKeyArgs;
import com.pulumi.oci.Dns.inputs.TsigKeyState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Tsig Key resource in Oracle Cloud Infrastructure DNS service.
 * 
 * Creates a new TSIG key in the specified compartment. There is no
 * `opc-retry-token` header since TSIG key names must be globally unique.
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
 * import com.pulumi.oci.Dns.TsigKey;
 * import com.pulumi.oci.Dns.TsigKeyArgs;
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
 *         var testTsigKey = new TsigKey("testTsigKey", TsigKeyArgs.builder()
 *             .algorithm(tsigKeyAlgorithm)
 *             .compartmentId(compartmentId)
 *             .name(tsigKeyName)
 *             .secret(tsigKeySecret)
 *             .definedTags(tsigKeyDefinedTags)
 *             .freeformTags(tsigKeyFreeformTags)
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
 * TsigKeys can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:Dns/tsigKey:TsigKey test_tsig_key &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Dns/tsigKey:TsigKey")
public class TsigKey extends com.pulumi.resources.CustomResource {
    /**
     * TSIG key algorithms are encoded as domain names, but most consist of only one non-empty label, which is not required to be explicitly absolute. Applicable algorithms include: hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha512. For more information on these algorithms, see [RFC 4635](https://tools.ietf.org/html/rfc4635#section-2).
     * 
     */
    @Export(name="algorithm", refs={String.class}, tree="[0]")
    private Output<String> algorithm;

    /**
     * @return TSIG key algorithms are encoded as domain names, but most consist of only one non-empty label, which is not required to be explicitly absolute. Applicable algorithms include: hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha512. For more information on these algorithms, see [RFC 4635](https://tools.ietf.org/html/rfc4635#section-2).
     * 
     */
    public Output<String> algorithm() {
        return this.algorithm;
    }
    /**
     * (Updatable) The OCID of the compartment containing the TSIG key.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment containing the TSIG key.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     * **Example:** `{&#34;Operations&#34;: {&#34;CostCenter&#34;: &#34;42&#34;}}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     * **Example:** `{&#34;Operations&#34;: {&#34;CostCenter&#34;: &#34;42&#34;}}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     * **Example:** `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     * **Example:** `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * A globally unique domain name identifying the key for a given pair of hosts.
     * 
     */
    @Export(name="name", refs={String.class}, tree="[0]")
    private Output<String> name;

    /**
     * @return A globally unique domain name identifying the key for a given pair of hosts.
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * A base64 string encoding the binary shared secret.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="secret", refs={String.class}, tree="[0]")
    private Output<String> secret;

    /**
     * @return A base64 string encoding the binary shared secret.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> secret() {
        return this.secret;
    }
    /**
     * The canonical absolute URL of the resource.
     * 
     */
    @Export(name="self", refs={String.class}, tree="[0]")
    private Output<String> self;

    /**
     * @return The canonical absolute URL of the resource.
     * 
     */
    public Output<String> self() {
        return this.self;
    }
    /**
     * The current state of the resource.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the resource.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The date and time the resource was created, expressed in RFC 3339 timestamp format.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The date and time the resource was created, expressed in RFC 3339 timestamp format.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The date and time the resource was last updated, expressed in RFC 3339 timestamp format.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The date and time the resource was last updated, expressed in RFC 3339 timestamp format.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public TsigKey(java.lang.String name) {
        this(name, TsigKeyArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public TsigKey(java.lang.String name, TsigKeyArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public TsigKey(java.lang.String name, TsigKeyArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Dns/tsigKey:TsigKey", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private TsigKey(java.lang.String name, Output<java.lang.String> id, @Nullable TsigKeyState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Dns/tsigKey:TsigKey", name, state, makeResourceOptions(options, id), false);
    }

    private static TsigKeyArgs makeArgs(TsigKeyArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? TsigKeyArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .additionalSecretOutputs(List.of(
                "secret"
            ))
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
    public static TsigKey get(java.lang.String name, Output<java.lang.String> id, @Nullable TsigKeyState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new TsigKey(name, id, state, options);
    }
}
