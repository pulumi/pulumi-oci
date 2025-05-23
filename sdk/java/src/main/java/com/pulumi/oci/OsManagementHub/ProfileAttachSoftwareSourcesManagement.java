// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.OsManagementHub.ProfileAttachSoftwareSourcesManagementArgs;
import com.pulumi.oci.OsManagementHub.inputs.ProfileAttachSoftwareSourcesManagementState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import javax.annotation.Nullable;

/**
 * This resource provides the Profile Attach Software Sources Management resource in Oracle Cloud Infrastructure Os Management Hub service.
 * 
 * Attaches the specified software sources to a profile.
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
 * import com.pulumi.oci.OsManagementHub.ProfileAttachSoftwareSourcesManagement;
 * import com.pulumi.oci.OsManagementHub.ProfileAttachSoftwareSourcesManagementArgs;
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
 *         var testProfileAttachSoftwareSourcesManagement = new ProfileAttachSoftwareSourcesManagement("testProfileAttachSoftwareSourcesManagement", ProfileAttachSoftwareSourcesManagementArgs.builder()
 *             .profileId(testProfile.id())
 *             .softwareSources(profileAttachSoftwareSourcesManagementSoftwareSources)
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
 * ProfileAttachSoftwareSourcesManagement can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:OsManagementHub/profileAttachSoftwareSourcesManagement:ProfileAttachSoftwareSourcesManagement test_profile_attach_software_sources_management &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:OsManagementHub/profileAttachSoftwareSourcesManagement:ProfileAttachSoftwareSourcesManagement")
public class ProfileAttachSoftwareSourcesManagement extends com.pulumi.resources.CustomResource {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
     * 
     */
    @Export(name="profileId", refs={String.class}, tree="[0]")
    private Output<String> profileId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
     * 
     */
    public Output<String> profileId() {
        return this.profileId;
    }
    /**
     * List of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to attach to the profile.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="softwareSources", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> softwareSources;

    /**
     * @return List of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to attach to the profile.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<List<String>> softwareSources() {
        return this.softwareSources;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ProfileAttachSoftwareSourcesManagement(java.lang.String name) {
        this(name, ProfileAttachSoftwareSourcesManagementArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ProfileAttachSoftwareSourcesManagement(java.lang.String name, ProfileAttachSoftwareSourcesManagementArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ProfileAttachSoftwareSourcesManagement(java.lang.String name, ProfileAttachSoftwareSourcesManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:OsManagementHub/profileAttachSoftwareSourcesManagement:ProfileAttachSoftwareSourcesManagement", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private ProfileAttachSoftwareSourcesManagement(java.lang.String name, Output<java.lang.String> id, @Nullable ProfileAttachSoftwareSourcesManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:OsManagementHub/profileAttachSoftwareSourcesManagement:ProfileAttachSoftwareSourcesManagement", name, state, makeResourceOptions(options, id), false);
    }

    private static ProfileAttachSoftwareSourcesManagementArgs makeArgs(ProfileAttachSoftwareSourcesManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ProfileAttachSoftwareSourcesManagementArgs.Empty : args;
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
    public static ProfileAttachSoftwareSourcesManagement get(java.lang.String name, Output<java.lang.String> id, @Nullable ProfileAttachSoftwareSourcesManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ProfileAttachSoftwareSourcesManagement(name, id, state, options);
    }
}
