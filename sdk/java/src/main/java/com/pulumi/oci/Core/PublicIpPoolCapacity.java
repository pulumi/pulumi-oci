// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Core.PublicIpPoolCapacityArgs;
import com.pulumi.oci.Core.inputs.PublicIpPoolCapacityState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import javax.annotation.Nullable;

/**
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
 * import com.pulumi.oci.Core.PublicIpPoolCapacity;
 * import com.pulumi.oci.Core.PublicIpPoolCapacityArgs;
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
 *         var testPublicIpPoolCapacity = new PublicIpPoolCapacity("testPublicIpPoolCapacity", PublicIpPoolCapacityArgs.builder()
 *             .publicIpPoolId(publicIpPoolId)
 *             .byoipId(byoipId)
 *             .cidrBlock(cidrBlock)
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
 * PublicIpPoolCapacity can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:Core/publicIpPoolCapacity:PublicIpPoolCapacity test_public_ip_pool_capacity &#34;publicIpPoolId/{publicIpPoolId}/byoipId/{byoipId}/cidrBlock/{cidrBlock}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Core/publicIpPoolCapacity:PublicIpPoolCapacity")
public class PublicIpPoolCapacity extends com.pulumi.resources.CustomResource {
    /**
     * The OCID of the Byoip Range Id object to which the cidr block belongs.
     * 
     */
    @Export(name="byoipId", refs={String.class}, tree="[0]")
    private Output<String> byoipId;

    /**
     * @return The OCID of the Byoip Range Id object to which the cidr block belongs.
     * 
     */
    public Output<String> byoipId() {
        return this.byoipId;
    }
    /**
     * The CIDR IP address range to be added to the Public Ip Pool. Example: `10.0.1.0/24`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="cidrBlock", refs={String.class}, tree="[0]")
    private Output<String> cidrBlock;

    /**
     * @return The CIDR IP address range to be added to the Public Ip Pool. Example: `10.0.1.0/24`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> cidrBlock() {
        return this.cidrBlock;
    }
    /**
     * The OCID of the pool object created by the current tenancy
     * 
     */
    @Export(name="publicIpPoolId", refs={String.class}, tree="[0]")
    private Output<String> publicIpPoolId;

    /**
     * @return The OCID of the pool object created by the current tenancy
     * 
     */
    public Output<String> publicIpPoolId() {
        return this.publicIpPoolId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public PublicIpPoolCapacity(java.lang.String name) {
        this(name, PublicIpPoolCapacityArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public PublicIpPoolCapacity(java.lang.String name, PublicIpPoolCapacityArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public PublicIpPoolCapacity(java.lang.String name, PublicIpPoolCapacityArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/publicIpPoolCapacity:PublicIpPoolCapacity", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private PublicIpPoolCapacity(java.lang.String name, Output<java.lang.String> id, @Nullable PublicIpPoolCapacityState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/publicIpPoolCapacity:PublicIpPoolCapacity", name, state, makeResourceOptions(options, id), false);
    }

    private static PublicIpPoolCapacityArgs makeArgs(PublicIpPoolCapacityArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? PublicIpPoolCapacityArgs.Empty : args;
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
    public static PublicIpPoolCapacity get(java.lang.String name, Output<java.lang.String> id, @Nullable PublicIpPoolCapacityState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new PublicIpPoolCapacity(name, id, state, options);
    }
}
