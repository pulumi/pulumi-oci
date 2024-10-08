// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ManagementDashboard;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.ManagementDashboard.ManagementDashboardsImportArgs;
import com.pulumi.oci.ManagementDashboard.inputs.ManagementDashboardsImportState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Management Dashboards Import resource in Oracle Cloud Infrastructure Management Dashboard service.
 * 
 * Imports an array of dashboards and their saved searches.
 * Here&#39;s an example of how you can use CLI to import a dashboard. For information on the details that must be passed to IMPORT, you can use the EXPORT API to obtain the Import.json file:
 * `oci management-dashboard dashboard export --query data --export-dashboard-id &#34;{\&#34;dashboardIds\&#34;:[\&#34;ocid1.managementdashboard.oc1..dashboardId1\&#34;]}&#34;  &gt; Import.json`.
 * Note that import API updates the resource if it already exists, and creates a new resource if it does not exist. To import to a different compartment, edit and change the compartmentId to the desired compartment OCID.
 * Here&#39;s an example of how you can use CLI to import:
 * `oci management-dashboard dashboard import --from-json file://Import.json`
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
 * import com.pulumi.oci.ManagementDashboard.ManagementDashboardsImport;
 * import com.pulumi.oci.ManagementDashboard.ManagementDashboardsImportArgs;
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
 *         var testManagementDashboardsImport = new ManagementDashboardsImport("testManagementDashboardsImport", ManagementDashboardsImportArgs.builder()
 *             .importDetails(sampleImportDetails)
 *             .importDetailsFile(sampleImportDetailsFilePath)
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
 * ManagementDashboardsImport can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:ManagementDashboard/managementDashboardsImport:ManagementDashboardsImport test_management_dashboards_import &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:ManagementDashboard/managementDashboardsImport:ManagementDashboardsImport")
public class ManagementDashboardsImport extends com.pulumi.resources.CustomResource {
    /**
     * Array of Dashboards to import. The `import_details` is mandatory if `import_details_path` is not passed. Value should be stringified JSON of [ManagementDashboardImportDetails](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/managementdashboard/20200901/ManagementDashboardImportDetails/)
     * 
     */
    @Export(name="importDetails", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> importDetails;

    /**
     * @return Array of Dashboards to import. The `import_details` is mandatory if `import_details_path` is not passed. Value should be stringified JSON of [ManagementDashboardImportDetails](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/managementdashboard/20200901/ManagementDashboardImportDetails/)
     * 
     */
    public Output<Optional<String>> importDetails() {
        return Codegen.optional(this.importDetails);
    }
    @Export(name="importDetailsFile", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> importDetailsFile;

    public Output<Optional<String>> importDetailsFile() {
        return Codegen.optional(this.importDetailsFile);
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ManagementDashboardsImport(java.lang.String name) {
        this(name, ManagementDashboardsImportArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ManagementDashboardsImport(java.lang.String name, @Nullable ManagementDashboardsImportArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ManagementDashboardsImport(java.lang.String name, @Nullable ManagementDashboardsImportArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:ManagementDashboard/managementDashboardsImport:ManagementDashboardsImport", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private ManagementDashboardsImport(java.lang.String name, Output<java.lang.String> id, @Nullable ManagementDashboardsImportState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:ManagementDashboard/managementDashboardsImport:ManagementDashboardsImport", name, state, makeResourceOptions(options, id), false);
    }

    private static ManagementDashboardsImportArgs makeArgs(@Nullable ManagementDashboardsImportArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ManagementDashboardsImportArgs.Empty : args;
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
    public static ManagementDashboardsImport get(java.lang.String name, Output<java.lang.String> id, @Nullable ManagementDashboardsImportState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ManagementDashboardsImport(name, id, state, options);
    }
}
