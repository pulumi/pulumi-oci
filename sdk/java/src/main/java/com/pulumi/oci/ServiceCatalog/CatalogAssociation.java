// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceCatalog;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.ServiceCatalog.CatalogAssociationArgs;
import com.pulumi.oci.ServiceCatalog.inputs.CatalogAssociationState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * This resource provides the Service Catalog Association resource in Oracle Cloud Infrastructure Service Catalog service.
 * 
 * Creates an association between service catalog and a resource.
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
 * import com.pulumi.oci.ServiceCatalog.CatalogAssociation;
 * import com.pulumi.oci.ServiceCatalog.CatalogAssociationArgs;
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
 *         var testServiceCatalogAssociation = new CatalogAssociation("testServiceCatalogAssociation", CatalogAssociationArgs.builder()
 *             .entityId(testEntity.id())
 *             .serviceCatalogId(testServiceCatalog.id())
 *             .entityType(serviceCatalogAssociationEntityType)
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
 * ServiceCatalogAssociations can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:ServiceCatalog/catalogAssociation:CatalogAssociation test_service_catalog_association &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:ServiceCatalog/catalogAssociation:CatalogAssociation")
public class CatalogAssociation extends com.pulumi.resources.CustomResource {
    /**
     * Identifier of the entity being associated with service catalog.
     * 
     */
    @Export(name="entityId", refs={String.class}, tree="[0]")
    private Output<String> entityId;

    /**
     * @return Identifier of the entity being associated with service catalog.
     * 
     */
    public Output<String> entityId() {
        return this.entityId;
    }
    /**
     * The type of the entity that is associated with the service catalog.
     * 
     */
    @Export(name="entityType", refs={String.class}, tree="[0]")
    private Output<String> entityType;

    /**
     * @return The type of the entity that is associated with the service catalog.
     * 
     */
    public Output<String> entityType() {
        return this.entityType;
    }
    /**
     * Identifier of the service catalog.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="serviceCatalogId", refs={String.class}, tree="[0]")
    private Output<String> serviceCatalogId;

    /**
     * @return Identifier of the service catalog.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> serviceCatalogId() {
        return this.serviceCatalogId;
    }
    /**
     * Timestamp of when the resource was associated with service catalog.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return Timestamp of when the resource was associated with service catalog.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public CatalogAssociation(java.lang.String name) {
        this(name, CatalogAssociationArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public CatalogAssociation(java.lang.String name, CatalogAssociationArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public CatalogAssociation(java.lang.String name, CatalogAssociationArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:ServiceCatalog/catalogAssociation:CatalogAssociation", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private CatalogAssociation(java.lang.String name, Output<java.lang.String> id, @Nullable CatalogAssociationState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:ServiceCatalog/catalogAssociation:CatalogAssociation", name, state, makeResourceOptions(options, id), false);
    }

    private static CatalogAssociationArgs makeArgs(CatalogAssociationArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? CatalogAssociationArgs.Empty : args;
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
    public static CatalogAssociation get(java.lang.String name, Output<java.lang.String> id, @Nullable CatalogAssociationState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new CatalogAssociation(name, id, state, options);
    }
}
