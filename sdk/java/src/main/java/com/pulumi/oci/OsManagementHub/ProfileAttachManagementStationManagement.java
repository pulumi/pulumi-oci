// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.OsManagementHub.ProfileAttachManagementStationManagementArgs;
import com.pulumi.oci.OsManagementHub.inputs.ProfileAttachManagementStationManagementState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * This resource provides the Profile Attach Management Station Management resource in Oracle Cloud Infrastructure Os Management Hub service.
 * 
 * Attaches the specified management station to a profile.
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
 * import com.pulumi.oci.OsManagementHub.ProfileAttachManagementStationManagement;
 * import com.pulumi.oci.OsManagementHub.ProfileAttachManagementStationManagementArgs;
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
 *         var testProfileAttachManagementStationManagement = new ProfileAttachManagementStationManagement("testProfileAttachManagementStationManagement", ProfileAttachManagementStationManagementArgs.builder()
 *             .managementStationId(testManagementStation.id())
 *             .profileId(testProfile.id())
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
 * ProfileAttachManagementStationManagement can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:OsManagementHub/profileAttachManagementStationManagement:ProfileAttachManagementStationManagement test_profile_attach_management_station_management &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:OsManagementHub/profileAttachManagementStationManagement:ProfileAttachManagementStationManagement")
public class ProfileAttachManagementStationManagement extends com.pulumi.resources.CustomResource {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station that the instance will be associated with.
     * 
     */
    @Export(name="managementStationId", refs={String.class}, tree="[0]")
    private Output<String> managementStationId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station that the instance will be associated with.
     * 
     */
    public Output<String> managementStationId() {
        return this.managementStationId;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="profileId", refs={String.class}, tree="[0]")
    private Output<String> profileId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> profileId() {
        return this.profileId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ProfileAttachManagementStationManagement(java.lang.String name) {
        this(name, ProfileAttachManagementStationManagementArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ProfileAttachManagementStationManagement(java.lang.String name, ProfileAttachManagementStationManagementArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ProfileAttachManagementStationManagement(java.lang.String name, ProfileAttachManagementStationManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:OsManagementHub/profileAttachManagementStationManagement:ProfileAttachManagementStationManagement", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private ProfileAttachManagementStationManagement(java.lang.String name, Output<java.lang.String> id, @Nullable ProfileAttachManagementStationManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:OsManagementHub/profileAttachManagementStationManagement:ProfileAttachManagementStationManagement", name, state, makeResourceOptions(options, id), false);
    }

    private static ProfileAttachManagementStationManagementArgs makeArgs(ProfileAttachManagementStationManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ProfileAttachManagementStationManagementArgs.Empty : args;
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
    public static ProfileAttachManagementStationManagement get(java.lang.String name, Output<java.lang.String> id, @Nullable ProfileAttachManagementStationManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ProfileAttachManagementStationManagement(name, id, state, options);
    }
}
