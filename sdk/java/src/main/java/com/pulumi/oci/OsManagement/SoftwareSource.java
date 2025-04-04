// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagement;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.OsManagement.SoftwareSourceArgs;
import com.pulumi.oci.OsManagement.inputs.SoftwareSourceState;
import com.pulumi.oci.OsManagement.outputs.SoftwareSourceAssociatedManagedInstance;
import com.pulumi.oci.Utilities;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Software Source resource in Oracle Cloud Infrastructure OS Management service.
 * 
 * Creates a new custom Software Source on the management system.
 * This will not contain any packages after it is first created,
 * and they must be added later.
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
 * import com.pulumi.oci.OsManagement.SoftwareSource;
 * import com.pulumi.oci.OsManagement.SoftwareSourceArgs;
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
 *         var testSoftwareSource = new SoftwareSource("testSoftwareSource", SoftwareSourceArgs.builder()
 *             .archType(softwareSourceArchType)
 *             .compartmentId(compartmentId)
 *             .displayName(softwareSourceDisplayName)
 *             .checksumType(softwareSourceChecksumType)
 *             .definedTags(Map.of("foo-namespace.bar-key", "value"))
 *             .description(softwareSourceDescription)
 *             .freeformTags(Map.of("bar-key", "value"))
 *             .maintainerEmail(softwareSourceMaintainerEmail)
 *             .maintainerName(softwareSourceMaintainerName)
 *             .maintainerPhone(softwareSourceMaintainerPhone)
 *             .parentId(testParent.id())
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
 * SoftwareSources can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:OsManagement/softwareSource:SoftwareSource test_software_source &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:OsManagement/softwareSource:SoftwareSource")
public class SoftwareSource extends com.pulumi.resources.CustomResource {
    /**
     * The architecture type supported by the Software Source
     * 
     */
    @Export(name="archType", refs={String.class}, tree="[0]")
    private Output<String> archType;

    /**
     * @return The architecture type supported by the Software Source
     * 
     */
    public Output<String> archType() {
        return this.archType;
    }
    /**
     * list of the Managed Instances associated with this Software Sources
     * 
     */
    @Export(name="associatedManagedInstances", refs={List.class,SoftwareSourceAssociatedManagedInstance.class}, tree="[0,1]")
    private Output<List<SoftwareSourceAssociatedManagedInstance>> associatedManagedInstances;

    /**
     * @return list of the Managed Instances associated with this Software Sources
     * 
     */
    public Output<List<SoftwareSourceAssociatedManagedInstance>> associatedManagedInstances() {
        return this.associatedManagedInstances;
    }
    /**
     * (Updatable) The yum repository checksum type used by this software source
     * 
     */
    @Export(name="checksumType", refs={String.class}, tree="[0]")
    private Output<String> checksumType;

    /**
     * @return (Updatable) The yum repository checksum type used by this software source
     * 
     */
    public Output<String> checksumType() {
        return this.checksumType;
    }
    /**
     * (Updatable) OCID for the Compartment
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) OCID for the Compartment
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
     * (Updatable) Information specified by the user about the software source
     * 
     */
    @Export(name="description", refs={String.class}, tree="[0]")
    private Output<String> description;

    /**
     * @return (Updatable) Information specified by the user about the software source
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) User friendly name for the software source
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) User friendly name for the software source
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
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
     * Fingerprint of the GPG key for this software source
     * 
     */
    @Export(name="gpgKeyFingerprint", refs={String.class}, tree="[0]")
    private Output<String> gpgKeyFingerprint;

    /**
     * @return Fingerprint of the GPG key for this software source
     * 
     */
    public Output<String> gpgKeyFingerprint() {
        return this.gpgKeyFingerprint;
    }
    /**
     * ID of the GPG key for this software source
     * 
     */
    @Export(name="gpgKeyId", refs={String.class}, tree="[0]")
    private Output<String> gpgKeyId;

    /**
     * @return ID of the GPG key for this software source
     * 
     */
    public Output<String> gpgKeyId() {
        return this.gpgKeyId;
    }
    /**
     * URL of the GPG key for this software source
     * 
     */
    @Export(name="gpgKeyUrl", refs={String.class}, tree="[0]")
    private Output<String> gpgKeyUrl;

    /**
     * @return URL of the GPG key for this software source
     * 
     */
    public Output<String> gpgKeyUrl() {
        return this.gpgKeyUrl;
    }
    /**
     * (Updatable) Email address of the person maintaining this software source
     * 
     */
    @Export(name="maintainerEmail", refs={String.class}, tree="[0]")
    private Output<String> maintainerEmail;

    /**
     * @return (Updatable) Email address of the person maintaining this software source
     * 
     */
    public Output<String> maintainerEmail() {
        return this.maintainerEmail;
    }
    /**
     * (Updatable) Name of the person maintaining this software source
     * 
     */
    @Export(name="maintainerName", refs={String.class}, tree="[0]")
    private Output<String> maintainerName;

    /**
     * @return (Updatable) Name of the person maintaining this software source
     * 
     */
    public Output<String> maintainerName() {
        return this.maintainerName;
    }
    /**
     * (Updatable) Phone number of the person maintaining this software source
     * 
     */
    @Export(name="maintainerPhone", refs={String.class}, tree="[0]")
    private Output<String> maintainerPhone;

    /**
     * @return (Updatable) Phone number of the person maintaining this software source
     * 
     */
    public Output<String> maintainerPhone() {
        return this.maintainerPhone;
    }
    /**
     * Number of packages
     * 
     */
    @Export(name="packages", refs={Integer.class}, tree="[0]")
    private Output<Integer> packages;

    /**
     * @return Number of packages
     * 
     */
    public Output<Integer> packages() {
        return this.packages;
    }
    /**
     * OCID for the parent software source, if there is one
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="parentId", refs={String.class}, tree="[0]")
    private Output<String> parentId;

    /**
     * @return OCID for the parent software source, if there is one
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> parentId() {
        return this.parentId;
    }
    /**
     * Display name the parent software source, if there is one
     * 
     */
    @Export(name="parentName", refs={String.class}, tree="[0]")
    private Output<String> parentName;

    /**
     * @return Display name the parent software source, if there is one
     * 
     */
    public Output<String> parentName() {
        return this.parentName;
    }
    /**
     * Type of the Software Source
     * 
     */
    @Export(name="repoType", refs={String.class}, tree="[0]")
    private Output<String> repoType;

    /**
     * @return Type of the Software Source
     * 
     */
    public Output<String> repoType() {
        return this.repoType;
    }
    /**
     * The current state of the Software Source.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the Software Source.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * status of the software source.
     * 
     */
    @Export(name="status", refs={String.class}, tree="[0]")
    private Output<String> status;

    /**
     * @return status of the software source.
     * 
     */
    public Output<String> status() {
        return this.status;
    }
    /**
     * URL for the repostiory
     * 
     */
    @Export(name="url", refs={String.class}, tree="[0]")
    private Output<String> url;

    /**
     * @return URL for the repostiory
     * 
     */
    public Output<String> url() {
        return this.url;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public SoftwareSource(java.lang.String name) {
        this(name, SoftwareSourceArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public SoftwareSource(java.lang.String name, SoftwareSourceArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public SoftwareSource(java.lang.String name, SoftwareSourceArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:OsManagement/softwareSource:SoftwareSource", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private SoftwareSource(java.lang.String name, Output<java.lang.String> id, @Nullable SoftwareSourceState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:OsManagement/softwareSource:SoftwareSource", name, state, makeResourceOptions(options, id), false);
    }

    private static SoftwareSourceArgs makeArgs(SoftwareSourceArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? SoftwareSourceArgs.Empty : args;
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
    public static SoftwareSource get(java.lang.String name, Output<java.lang.String> id, @Nullable SoftwareSourceState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new SoftwareSource(name, id, state, options);
    }
}
