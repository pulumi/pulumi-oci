// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.OsManagementHub.ManagedInstanceAttachProfileManagementArgs;
import com.pulumi.oci.OsManagementHub.inputs.ManagedInstanceAttachProfileManagementState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * This resource provides the Managed Instance Attach Profile Management resource in Oracle Cloud Infrastructure Os Management Hub service.
 * 
 * Adds profile to a managed instance. After the profile has been added,
 * the instance can be registered as a managed instance.
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
 * import com.pulumi.oci.OsManagementHub.ManagedInstanceAttachProfileManagement;
 * import com.pulumi.oci.OsManagementHub.ManagedInstanceAttachProfileManagementArgs;
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
 *         var testManagedInstanceAttachProfileManagement = new ManagedInstanceAttachProfileManagement("testManagedInstanceAttachProfileManagement", ManagedInstanceAttachProfileManagementArgs.builder()
 *             .managedInstanceId(testManagedInstance.id())
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
 * ManagedInstanceAttachProfileManagement can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:OsManagementHub/managedInstanceAttachProfileManagement:ManagedInstanceAttachProfileManagement test_managed_instance_attach_profile_management &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:OsManagementHub/managedInstanceAttachProfileManagement:ManagedInstanceAttachProfileManagement")
public class ManagedInstanceAttachProfileManagement extends com.pulumi.resources.CustomResource {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
     * 
     */
    @Export(name="managedInstanceId", refs={String.class}, tree="[0]")
    private Output<String> managedInstanceId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
     * 
     */
    public Output<String> managedInstanceId() {
        return this.managedInstanceId;
    }
    /**
     * The profile [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to attach to the managed instance.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="profileId", refs={String.class}, tree="[0]")
    private Output<String> profileId;

    /**
     * @return The profile [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to attach to the managed instance.
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
    public ManagedInstanceAttachProfileManagement(java.lang.String name) {
        this(name, ManagedInstanceAttachProfileManagementArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ManagedInstanceAttachProfileManagement(java.lang.String name, ManagedInstanceAttachProfileManagementArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ManagedInstanceAttachProfileManagement(java.lang.String name, ManagedInstanceAttachProfileManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:OsManagementHub/managedInstanceAttachProfileManagement:ManagedInstanceAttachProfileManagement", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private ManagedInstanceAttachProfileManagement(java.lang.String name, Output<java.lang.String> id, @Nullable ManagedInstanceAttachProfileManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:OsManagementHub/managedInstanceAttachProfileManagement:ManagedInstanceAttachProfileManagement", name, state, makeResourceOptions(options, id), false);
    }

    private static ManagedInstanceAttachProfileManagementArgs makeArgs(ManagedInstanceAttachProfileManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ManagedInstanceAttachProfileManagementArgs.Empty : args;
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
    public static ManagedInstanceAttachProfileManagement get(java.lang.String name, Output<java.lang.String> id, @Nullable ManagedInstanceAttachProfileManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ManagedInstanceAttachProfileManagement(name, id, state, options);
    }
}
