// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DatabaseManagement.ExternalExadataInfrastructureArgs;
import com.pulumi.oci.DatabaseManagement.inputs.ExternalExadataInfrastructureState;
import com.pulumi.oci.DatabaseManagement.outputs.ExternalExadataInfrastructureDatabaseSystem;
import com.pulumi.oci.DatabaseManagement.outputs.ExternalExadataInfrastructureStorageGrid;
import com.pulumi.oci.Utilities;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the External Exadata Infrastructure resource in Oracle Cloud Infrastructure Database Management service.
 * 
 * Creates an Oracle Cloud Infrastructure resource for the Exadata infrastructure and enables the Monitoring service for the Exadata infrastructure.
 * The following resource/subresources are created:
 *   Infrastructure
 *   Storage server connectors
 *   Storage servers
 *   Storage grids
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.DatabaseManagement.ExternalExadataInfrastructure;
 * import com.pulumi.oci.DatabaseManagement.ExternalExadataInfrastructureArgs;
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
 *         var testExternalExadataInfrastructure = new ExternalExadataInfrastructure(&#34;testExternalExadataInfrastructure&#34;, ExternalExadataInfrastructureArgs.builder()        
 *             .compartmentId(var_.compartment_id())
 *             .dbSystemIds(var_.external_exadata_infrastructure_db_system_ids())
 *             .displayName(var_.external_exadata_infrastructure_display_name())
 *             .discoveryKey(var_.external_exadata_infrastructure_discovery_key())
 *             .licenseModel(var_.external_exadata_infrastructure_license_model())
 *             .storageServerNames(var_.external_exadata_infrastructure_storage_server_names())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * ExternalExadataInfrastructures can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:DatabaseManagement/externalExadataInfrastructure:ExternalExadataInfrastructure test_external_exadata_infrastructure &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:DatabaseManagement/externalExadataInfrastructure:ExternalExadataInfrastructure")
public class ExternalExadataInfrastructure extends com.pulumi.resources.CustomResource {
    /**
     * The additional details of the resource defined in `{&#34;key&#34;: &#34;value&#34;}` format. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="additionalDetails", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> additionalDetails;

    /**
     * @return The additional details of the resource defined in `{&#34;key&#34;: &#34;value&#34;}` format. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> additionalDetails() {
        return this.additionalDetails;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * The list of [OCIDs] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartments.
     * 
     */
    @Export(name="databaseCompartments", type=List.class, parameters={String.class})
    private Output<List<String>> databaseCompartments;

    /**
     * @return The list of [OCIDs] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartments.
     * 
     */
    public Output<List<String>> databaseCompartments() {
        return this.databaseCompartments;
    }
    /**
     * A list of DB systems.
     * 
     */
    @Export(name="databaseSystems", type=List.class, parameters={ExternalExadataInfrastructureDatabaseSystem.class})
    private Output<List<ExternalExadataInfrastructureDatabaseSystem>> databaseSystems;

    /**
     * @return A list of DB systems.
     * 
     */
    public Output<List<ExternalExadataInfrastructureDatabaseSystem>> databaseSystems() {
        return this.databaseSystems;
    }
    /**
     * (Updatable) The list of DB systems in the Exadata infrastructure.
     * 
     */
    @Export(name="dbSystemIds", type=List.class, parameters={String.class})
    private Output<List<String>> dbSystemIds;

    /**
     * @return (Updatable) The list of DB systems in the Exadata infrastructure.
     * 
     */
    public Output<List<String>> dbSystemIds() {
        return this.dbSystemIds;
    }
    /**
     * (Updatable) The unique key of the discovery request.
     * 
     */
    @Export(name="discoveryKey", type=String.class, parameters={})
    private Output<String> discoveryKey;

    /**
     * @return (Updatable) The unique key of the discovery request.
     * 
     */
    public Output<String> discoveryKey() {
        return this.discoveryKey;
    }
    /**
     * (Updatable) The name of the Exadata infrastructure.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) The name of the Exadata infrastructure.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * The internal ID of the Exadata resource.
     * 
     */
    @Export(name="internalId", type=String.class, parameters={})
    private Output<String> internalId;

    /**
     * @return The internal ID of the Exadata resource.
     * 
     */
    public Output<String> internalId() {
        return this.internalId;
    }
    /**
     * (Updatable) The Oracle license model that applies to the database management resources.
     * 
     */
    @Export(name="licenseModel", type=String.class, parameters={})
    private Output<String> licenseModel;

    /**
     * @return (Updatable) The Oracle license model that applies to the database management resources.
     * 
     */
    public Output<String> licenseModel() {
        return this.licenseModel;
    }
    /**
     * The details of the lifecycle state of the Exadata resource.
     * 
     */
    @Export(name="lifecycleDetails", type=String.class, parameters={})
    private Output<String> lifecycleDetails;

    /**
     * @return The details of the lifecycle state of the Exadata resource.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * The rack size of the Exadata infrastructure.
     * 
     */
    @Export(name="rackSize", type=String.class, parameters={})
    private Output<String> rackSize;

    /**
     * @return The rack size of the Exadata infrastructure.
     * 
     */
    public Output<String> rackSize() {
        return this.rackSize;
    }
    /**
     * The current lifecycle state of the database resource.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current lifecycle state of the database resource.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The status of the Exadata resource.
     * 
     */
    @Export(name="status", type=String.class, parameters={})
    private Output<String> status;

    /**
     * @return The status of the Exadata resource.
     * 
     */
    public Output<String> status() {
        return this.status;
    }
    /**
     * The Exadata storage server grid of the Exadata infrastructure.
     * 
     */
    @Export(name="storageGrids", type=List.class, parameters={ExternalExadataInfrastructureStorageGrid.class})
    private Output<List<ExternalExadataInfrastructureStorageGrid>> storageGrids;

    /**
     * @return The Exadata storage server grid of the Exadata infrastructure.
     * 
     */
    public Output<List<ExternalExadataInfrastructureStorageGrid>> storageGrids() {
        return this.storageGrids;
    }
    /**
     * (Updatable) The list of all the Exadata storage server names to be included for monitoring purposes. If not specified, all the Exadata storage servers associated with the DB systems are included.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="storageServerNames", type=List.class, parameters={String.class})
    private Output</* @Nullable */ List<String>> storageServerNames;

    /**
     * @return (Updatable) The list of all the Exadata storage server names to be included for monitoring purposes. If not specified, all the Exadata storage servers associated with the DB systems are included.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<Optional<List<String>>> storageServerNames() {
        return Codegen.optional(this.storageServerNames);
    }
    /**
     * The timestamp of the creation of the Exadata resource.
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The timestamp of the creation of the Exadata resource.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The timestamp of the last update of the Exadata resource.
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return The timestamp of the last update of the Exadata resource.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * The version of the Exadata resource.
     * 
     */
    @Export(name="version", type=String.class, parameters={})
    private Output<String> version;

    /**
     * @return The version of the Exadata resource.
     * 
     */
    public Output<String> version() {
        return this.version;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ExternalExadataInfrastructure(String name) {
        this(name, ExternalExadataInfrastructureArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ExternalExadataInfrastructure(String name, ExternalExadataInfrastructureArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ExternalExadataInfrastructure(String name, ExternalExadataInfrastructureArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DatabaseManagement/externalExadataInfrastructure:ExternalExadataInfrastructure", name, args == null ? ExternalExadataInfrastructureArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private ExternalExadataInfrastructure(String name, Output<String> id, @Nullable ExternalExadataInfrastructureState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DatabaseManagement/externalExadataInfrastructure:ExternalExadataInfrastructure", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
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
    public static ExternalExadataInfrastructure get(String name, Output<String> id, @Nullable ExternalExadataInfrastructureState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ExternalExadataInfrastructure(name, id, state, options);
    }
}