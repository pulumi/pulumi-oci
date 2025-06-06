// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.OsManagementHub.ProfileAttachLifecycleStageManagementArgs;
import com.pulumi.oci.OsManagementHub.inputs.ProfileAttachLifecycleStageManagementState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * This resource provides the Profile Attach Lifecycle Stage Management resource in Oracle Cloud Infrastructure Os Management Hub service.
 * 
 * Attaches the specified lifecycle stage to a profile.
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
 * import com.pulumi.oci.OsManagementHub.ProfileAttachLifecycleStageManagement;
 * import com.pulumi.oci.OsManagementHub.ProfileAttachLifecycleStageManagementArgs;
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
 *         var testProfileAttachLifecycleStageManagement = new ProfileAttachLifecycleStageManagement("testProfileAttachLifecycleStageManagement", ProfileAttachLifecycleStageManagementArgs.builder()
 *             .lifecycleStageId(testLifecycleStage.id())
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
 * ProfileAttachLifecycleStageManagement can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:OsManagementHub/profileAttachLifecycleStageManagement:ProfileAttachLifecycleStageManagement test_profile_attach_lifecycle_stage_management &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:OsManagementHub/profileAttachLifecycleStageManagement:ProfileAttachLifecycleStageManagement")
public class ProfileAttachLifecycleStageManagement extends com.pulumi.resources.CustomResource {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage that the instance will be associated with.
     * 
     */
    @Export(name="lifecycleStageId", refs={String.class}, tree="[0]")
    private Output<String> lifecycleStageId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage that the instance will be associated with.
     * 
     */
    public Output<String> lifecycleStageId() {
        return this.lifecycleStageId;
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
    public ProfileAttachLifecycleStageManagement(java.lang.String name) {
        this(name, ProfileAttachLifecycleStageManagementArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ProfileAttachLifecycleStageManagement(java.lang.String name, ProfileAttachLifecycleStageManagementArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ProfileAttachLifecycleStageManagement(java.lang.String name, ProfileAttachLifecycleStageManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:OsManagementHub/profileAttachLifecycleStageManagement:ProfileAttachLifecycleStageManagement", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private ProfileAttachLifecycleStageManagement(java.lang.String name, Output<java.lang.String> id, @Nullable ProfileAttachLifecycleStageManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:OsManagementHub/profileAttachLifecycleStageManagement:ProfileAttachLifecycleStageManagement", name, state, makeResourceOptions(options, id), false);
    }

    private static ProfileAttachLifecycleStageManagementArgs makeArgs(ProfileAttachLifecycleStageManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ProfileAttachLifecycleStageManagementArgs.Empty : args;
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
    public static ProfileAttachLifecycleStageManagement get(java.lang.String name, Output<java.lang.String> id, @Nullable ProfileAttachLifecycleStageManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ProfileAttachLifecycleStageManagement(name, id, state, options);
    }
}
