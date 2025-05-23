// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DevOps.RepositoryMirrorArgs;
import com.pulumi.oci.DevOps.inputs.RepositoryMirrorState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * This resource provides the Repository Mirror resource in Oracle Cloud Infrastructure Devops service.
 * 
 * Synchronize a mirrored repository to the latest version from external providers.
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
 * import com.pulumi.oci.DevOps.RepositoryMirror;
 * import com.pulumi.oci.DevOps.RepositoryMirrorArgs;
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
 *         var testRepositoryMirror = new RepositoryMirror("testRepositoryMirror", RepositoryMirrorArgs.builder()
 *             .repositoryId(testRepository.id())
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
 * RepositoryMirror can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:DevOps/repositoryMirror:RepositoryMirror test_repository_mirror &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:DevOps/repositoryMirror:RepositoryMirror")
public class RepositoryMirror extends com.pulumi.resources.CustomResource {
    /**
     * Unique repository identifier.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="repositoryId", refs={String.class}, tree="[0]")
    private Output<String> repositoryId;

    /**
     * @return Unique repository identifier.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> repositoryId() {
        return this.repositoryId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public RepositoryMirror(java.lang.String name) {
        this(name, RepositoryMirrorArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public RepositoryMirror(java.lang.String name, RepositoryMirrorArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public RepositoryMirror(java.lang.String name, RepositoryMirrorArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DevOps/repositoryMirror:RepositoryMirror", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private RepositoryMirror(java.lang.String name, Output<java.lang.String> id, @Nullable RepositoryMirrorState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DevOps/repositoryMirror:RepositoryMirror", name, state, makeResourceOptions(options, id), false);
    }

    private static RepositoryMirrorArgs makeArgs(RepositoryMirrorArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? RepositoryMirrorArgs.Empty : args;
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
    public static RepositoryMirror get(java.lang.String name, Output<java.lang.String> id, @Nullable RepositoryMirrorState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new RepositoryMirror(name, id, state, options);
    }
}
