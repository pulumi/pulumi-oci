// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CapacityManagement;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.CapacityManagement.OccAvailabilityCatalogArgs;
import com.pulumi.oci.CapacityManagement.inputs.OccAvailabilityCatalogState;
import com.pulumi.oci.CapacityManagement.outputs.OccAvailabilityCatalogDetail;
import com.pulumi.oci.CapacityManagement.outputs.OccAvailabilityCatalogMetadataDetails;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Occ Availability Catalog resource in Oracle Cloud Infrastructure Capacity Management service.
 * 
 * Create availability catalog
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
 * import com.pulumi.oci.CapacityManagement.OccAvailabilityCatalog;
 * import com.pulumi.oci.CapacityManagement.OccAvailabilityCatalogArgs;
 * import com.pulumi.oci.CapacityManagement.inputs.OccAvailabilityCatalogMetadataDetailsArgs;
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
 *         var testOccAvailabilityCatalog = new OccAvailabilityCatalog("testOccAvailabilityCatalog", OccAvailabilityCatalogArgs.builder()
 *             .base64encodedCatalogDetails(occAvailabilityCatalogBase64encodedCatalogDetails)
 *             .compartmentId(compartmentId)
 *             .displayName(occAvailabilityCatalogDisplayName)
 *             .namespace(occAvailabilityCatalogNamespace)
 *             .occCustomerGroupId(testOccCustomerGroup.id())
 *             .definedTags(Map.of("foo-namespace.bar-key", "value"))
 *             .description(occAvailabilityCatalogDescription)
 *             .freeformTags(Map.of("bar-key", "value"))
 *             .metadataDetails(OccAvailabilityCatalogMetadataDetailsArgs.builder()
 *                 .formatVersion(occAvailabilityCatalogMetadataDetailsFormatVersion)
 *                 .build())
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
 * OccAvailabilityCatalogs can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:CapacityManagement/occAvailabilityCatalog:OccAvailabilityCatalog test_occ_availability_catalog &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:CapacityManagement/occAvailabilityCatalog:OccAvailabilityCatalog")
public class OccAvailabilityCatalog extends com.pulumi.resources.CustomResource {
    /**
     * The base 64 encoded string corresponding to the catalog file contents.
     * 
     */
    @Export(name="base64encodedCatalogDetails", refs={String.class}, tree="[0]")
    private Output<String> base64encodedCatalogDetails;

    /**
     * @return The base 64 encoded string corresponding to the catalog file contents.
     * 
     */
    public Output<String> base64encodedCatalogDetails() {
        return this.base64encodedCatalogDetails;
    }
    /**
     * The different states associated with the availability catalog.
     * 
     */
    @Export(name="catalogState", refs={String.class}, tree="[0]")
    private Output<String> catalogState;

    /**
     * @return The different states associated with the availability catalog.
     * 
     */
    public Output<String> catalogState() {
        return this.catalogState;
    }
    /**
     * Since all resources are at tenancy level hence this will be the ocid of the tenancy where operation is to be performed.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return Since all resources are at tenancy level hence this will be the ocid of the tenancy where operation is to be performed.
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
     * (Updatable) Additional information about the availability catalog.
     * 
     */
    @Export(name="description", refs={String.class}, tree="[0]")
    private Output<String> description;

    /**
     * @return (Updatable) Additional information about the availability catalog.
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * Details about capacity available for different resources in catalog.
     * 
     */
    @Export(name="details", refs={List.class,OccAvailabilityCatalogDetail.class}, tree="[0,1]")
    private Output<List<OccAvailabilityCatalogDetail>> details;

    /**
     * @return Details about capacity available for different resources in catalog.
     * 
     */
    public Output<List<OccAvailabilityCatalogDetail>> details() {
        return this.details;
    }
    /**
     * (Updatable) The display name of the availability catalog.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) The display name of the availability catalog.
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
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed State.
     * 
     */
    @Export(name="lifecycleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed State.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * Used for representing the metadata of the catalog. This denotes the version and format of the CSV file for parsing.
     * 
     */
    @Export(name="metadataDetails", refs={OccAvailabilityCatalogMetadataDetails.class}, tree="[0]")
    private Output<OccAvailabilityCatalogMetadataDetails> metadataDetails;

    /**
     * @return Used for representing the metadata of the catalog. This denotes the version and format of the CSV file for parsing.
     * 
     */
    public Output<OccAvailabilityCatalogMetadataDetails> metadataDetails() {
        return this.metadataDetails;
    }
    /**
     * The name of the Oracle Cloud Infrastructure service in consideration. For example, Compute, Exadata, and so on.
     * 
     */
    @Export(name="namespace", refs={String.class}, tree="[0]")
    private Output<String> namespace;

    /**
     * @return The name of the Oracle Cloud Infrastructure service in consideration. For example, Compute, Exadata, and so on.
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }
    /**
     * The OCID of the customer group.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="occCustomerGroupId", refs={String.class}, tree="[0]")
    private Output<String> occCustomerGroupId;

    /**
     * @return The OCID of the customer group.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> occCustomerGroupId() {
        return this.occCustomerGroupId;
    }
    /**
     * The current lifecycle state of the resource.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current lifecycle state of the resource.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,String>> systemTags() {
        return this.systemTags;
    }
    /**
     * The time when the availability catalog was created.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The time when the availability catalog was created.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time when the availability catalog was last updated.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The time when the availability catalog was last updated.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public OccAvailabilityCatalog(java.lang.String name) {
        this(name, OccAvailabilityCatalogArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public OccAvailabilityCatalog(java.lang.String name, OccAvailabilityCatalogArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public OccAvailabilityCatalog(java.lang.String name, OccAvailabilityCatalogArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:CapacityManagement/occAvailabilityCatalog:OccAvailabilityCatalog", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private OccAvailabilityCatalog(java.lang.String name, Output<java.lang.String> id, @Nullable OccAvailabilityCatalogState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:CapacityManagement/occAvailabilityCatalog:OccAvailabilityCatalog", name, state, makeResourceOptions(options, id), false);
    }

    private static OccAvailabilityCatalogArgs makeArgs(OccAvailabilityCatalogArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? OccAvailabilityCatalogArgs.Empty : args;
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
    public static OccAvailabilityCatalog get(java.lang.String name, Output<java.lang.String> id, @Nullable OccAvailabilityCatalogState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new OccAvailabilityCatalog(name, id, state, options);
    }
}
