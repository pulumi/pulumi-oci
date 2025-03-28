// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.OsManagementHub.SoftwareSourceManifestArgs;
import com.pulumi.oci.OsManagementHub.inputs.SoftwareSourceManifestState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Software Source Manifest resource in Oracle Cloud Infrastructure Os Management Hub service.
 * 
 * Updates the package list document for the software source.
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
 * import com.pulumi.oci.OsManagementHub.SoftwareSourceManifest;
 * import com.pulumi.oci.OsManagementHub.SoftwareSourceManifestArgs;
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
 *         var testSoftwareSourceManifest = new SoftwareSourceManifest("testSoftwareSourceManifest", SoftwareSourceManifestArgs.builder()
 *             .softwareSourceId(testSoftwareSource.id())
 *             .content(content)
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
 * SoftwareSourceManifests can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:OsManagementHub/softwareSourceManifest:SoftwareSourceManifest test_software_source_manifest &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:OsManagementHub/softwareSourceManifest:SoftwareSourceManifest")
public class SoftwareSourceManifest extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) Provides the manifest content used to update the package list of the software source.
     * 
     */
    @Export(name="content", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> content;

    /**
     * @return (Updatable) Provides the manifest content used to update the package list of the software source.
     * 
     */
    public Output<Optional<String>> content() {
        return Codegen.optional(this.content);
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="softwareSourceId", refs={String.class}, tree="[0]")
    private Output<String> softwareSourceId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> softwareSourceId() {
        return this.softwareSourceId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public SoftwareSourceManifest(java.lang.String name) {
        this(name, SoftwareSourceManifestArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public SoftwareSourceManifest(java.lang.String name, SoftwareSourceManifestArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public SoftwareSourceManifest(java.lang.String name, SoftwareSourceManifestArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:OsManagementHub/softwareSourceManifest:SoftwareSourceManifest", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private SoftwareSourceManifest(java.lang.String name, Output<java.lang.String> id, @Nullable SoftwareSourceManifestState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:OsManagementHub/softwareSourceManifest:SoftwareSourceManifest", name, state, makeResourceOptions(options, id), false);
    }

    private static SoftwareSourceManifestArgs makeArgs(SoftwareSourceManifestArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? SoftwareSourceManifestArgs.Empty : args;
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
    public static SoftwareSourceManifest get(java.lang.String name, Output<java.lang.String> id, @Nullable SoftwareSourceManifestState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new SoftwareSourceManifest(name, id, state, options);
    }
}
