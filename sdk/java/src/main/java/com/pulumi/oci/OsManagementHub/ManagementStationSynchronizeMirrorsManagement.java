// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.OsManagementHub.ManagementStationSynchronizeMirrorsManagementArgs;
import com.pulumi.oci.OsManagementHub.inputs.ManagementStationSynchronizeMirrorsManagementState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import javax.annotation.Nullable;

/**
 * This resource provides the Management Station Synchronize Mirrors Management resource in Oracle Cloud Infrastructure Os Management Hub service.
 * 
 * Synchronize the specified software sources mirrored on the management station.
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
 * import com.pulumi.oci.OsManagementHub.ManagementStationSynchronizeMirrorsManagement;
 * import com.pulumi.oci.OsManagementHub.ManagementStationSynchronizeMirrorsManagementArgs;
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
 *         var testManagementStationSynchronizeMirrorsManagement = new ManagementStationSynchronizeMirrorsManagement("testManagementStationSynchronizeMirrorsManagement", ManagementStationSynchronizeMirrorsManagementArgs.builder()
 *             .managementStationId(testManagementStation.id())
 *             .softwareSourceLists(managementStationSynchronizeMirrorsManagementSoftwareSourceList)
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
 * ManagementStationSynchronizeMirrorsManagement can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:OsManagementHub/managementStationSynchronizeMirrorsManagement:ManagementStationSynchronizeMirrorsManagement test_management_station_synchronize_mirrors_management &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:OsManagementHub/managementStationSynchronizeMirrorsManagement:ManagementStationSynchronizeMirrorsManagement")
public class ManagementStationSynchronizeMirrorsManagement extends com.pulumi.resources.CustomResource {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
     * 
     */
    @Export(name="managementStationId", refs={String.class}, tree="[0]")
    private Output<String> managementStationId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
     * 
     */
    public Output<String> managementStationId() {
        return this.managementStationId;
    }
    /**
     * List of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to synchronize.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="softwareSourceLists", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> softwareSourceLists;

    /**
     * @return List of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to synchronize.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<List<String>> softwareSourceLists() {
        return this.softwareSourceLists;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ManagementStationSynchronizeMirrorsManagement(java.lang.String name) {
        this(name, ManagementStationSynchronizeMirrorsManagementArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ManagementStationSynchronizeMirrorsManagement(java.lang.String name, ManagementStationSynchronizeMirrorsManagementArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ManagementStationSynchronizeMirrorsManagement(java.lang.String name, ManagementStationSynchronizeMirrorsManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:OsManagementHub/managementStationSynchronizeMirrorsManagement:ManagementStationSynchronizeMirrorsManagement", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private ManagementStationSynchronizeMirrorsManagement(java.lang.String name, Output<java.lang.String> id, @Nullable ManagementStationSynchronizeMirrorsManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:OsManagementHub/managementStationSynchronizeMirrorsManagement:ManagementStationSynchronizeMirrorsManagement", name, state, makeResourceOptions(options, id), false);
    }

    private static ManagementStationSynchronizeMirrorsManagementArgs makeArgs(ManagementStationSynchronizeMirrorsManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ManagementStationSynchronizeMirrorsManagementArgs.Empty : args;
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
    public static ManagementStationSynchronizeMirrorsManagement get(java.lang.String name, Output<java.lang.String> id, @Nullable ManagementStationSynchronizeMirrorsManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ManagementStationSynchronizeMirrorsManagement(name, id, state, options);
    }
}
