// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Database.ExternalContainerDatabaseArgs;
import com.pulumi.oci.Database.inputs.ExternalContainerDatabaseState;
import com.pulumi.oci.Database.outputs.ExternalContainerDatabaseDatabaseManagementConfig;
import com.pulumi.oci.Database.outputs.ExternalContainerDatabaseStackMonitoringConfig;
import com.pulumi.oci.Utilities;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the External Container Database resource in Oracle Cloud Infrastructure Database service.
 * 
 * Creates a new external container database resource.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.Database.ExternalContainerDatabase;
 * import com.pulumi.oci.Database.ExternalContainerDatabaseArgs;
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
 *         var testExternalContainerDatabase = new ExternalContainerDatabase(&#34;testExternalContainerDatabase&#34;, ExternalContainerDatabaseArgs.builder()        
 *             .compartmentId(var_.compartment_id())
 *             .displayName(var_.external_container_database_display_name())
 *             .definedTags(var_.external_container_database_defined_tags())
 *             .freeformTags(Map.of(&#34;Department&#34;, &#34;Finance&#34;))
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * ExternalContainerDatabases can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Database/externalContainerDatabase:ExternalContainerDatabase test_external_container_database &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Database/externalContainerDatabase:ExternalContainerDatabase")
public class ExternalContainerDatabase extends com.pulumi.resources.CustomResource {
    /**
     * The character set of the external database.
     * 
     */
    @Export(name="characterSet", type=String.class, parameters={})
    private Output<String> characterSet;

    /**
     * @return The character set of the external database.
     * 
     */
    public Output<String> characterSet() {
        return this.characterSet;
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
     * The Oracle Database configuration
     * 
     */
    @Export(name="databaseConfiguration", type=String.class, parameters={})
    private Output<String> databaseConfiguration;

    /**
     * @return The Oracle Database configuration
     * 
     */
    public Output<String> databaseConfiguration() {
        return this.databaseConfiguration;
    }
    /**
     * The Oracle Database edition.
     * 
     */
    @Export(name="databaseEdition", type=String.class, parameters={})
    private Output<String> databaseEdition;

    /**
     * @return The Oracle Database edition.
     * 
     */
    public Output<String> databaseEdition() {
        return this.databaseEdition;
    }
    /**
     * The configuration of the Database Management service.
     * 
     */
    @Export(name="databaseManagementConfigs", type=List.class, parameters={ExternalContainerDatabaseDatabaseManagementConfig.class})
    private Output<List<ExternalContainerDatabaseDatabaseManagementConfig>> databaseManagementConfigs;

    /**
     * @return The configuration of the Database Management service.
     * 
     */
    public Output<List<ExternalContainerDatabaseDatabaseManagementConfig>> databaseManagementConfigs() {
        return this.databaseManagementConfigs;
    }
    /**
     * The Oracle Database version.
     * 
     */
    @Export(name="databaseVersion", type=String.class, parameters={})
    private Output<String> databaseVersion;

    /**
     * @return The Oracle Database version.
     * 
     */
    public Output<String> databaseVersion() {
        return this.databaseVersion;
    }
    /**
     * The Oracle Database ID, which identifies an Oracle Database located outside of Oracle Cloud.
     * 
     */
    @Export(name="dbId", type=String.class, parameters={})
    private Output<String> dbId;

    /**
     * @return The Oracle Database ID, which identifies an Oracle Database located outside of Oracle Cloud.
     * 
     */
    public Output<String> dbId() {
        return this.dbId;
    }
    /**
     * The database packs licensed for the external Oracle Database.
     * 
     */
    @Export(name="dbPacks", type=String.class, parameters={})
    private Output<String> dbPacks;

    /**
     * @return The database packs licensed for the external Oracle Database.
     * 
     */
    public Output<String> dbPacks() {
        return this.dbPacks;
    }
    /**
     * The `DB_UNIQUE_NAME` of the external database.
     * 
     */
    @Export(name="dbUniqueName", type=String.class, parameters={})
    private Output<String> dbUniqueName;

    /**
     * @return The `DB_UNIQUE_NAME` of the external database.
     * 
     */
    public Output<String> dbUniqueName() {
        return this.dbUniqueName;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) The user-friendly name for the external database. The name does not have to be unique.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) The user-friendly name for the external database. The name does not have to be unique.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * Additional information about the current lifecycle state.
     * 
     */
    @Export(name="lifecycleDetails", type=String.class, parameters={})
    private Output<String> lifecycleDetails;

    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * The national character of the external database.
     * 
     */
    @Export(name="ncharacterSet", type=String.class, parameters={})
    private Output<String> ncharacterSet;

    /**
     * @return The national character of the external database.
     * 
     */
    public Output<String> ncharacterSet() {
        return this.ncharacterSet;
    }
    /**
     * The configuration of Stack Monitoring for the external database.
     * 
     */
    @Export(name="stackMonitoringConfigs", type=List.class, parameters={ExternalContainerDatabaseStackMonitoringConfig.class})
    private Output<List<ExternalContainerDatabaseStackMonitoringConfig>> stackMonitoringConfigs;

    /**
     * @return The configuration of Stack Monitoring for the external database.
     * 
     */
    public Output<List<ExternalContainerDatabaseStackMonitoringConfig>> stackMonitoringConfigs() {
        return this.stackMonitoringConfigs;
    }
    /**
     * The current state of the Oracle Cloud Infrastructure external database resource.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the Oracle Cloud Infrastructure external database resource.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The date and time the database was created.
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the database was created.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time zone of the external database. It is a time zone offset (a character type in the format &#39;[+|-]TZH:TZM&#39;) or a time zone region name, depending on how the time zone value was specified when the database was created / last altered.
     * 
     */
    @Export(name="timeZone", type=String.class, parameters={})
    private Output<String> timeZone;

    /**
     * @return The time zone of the external database. It is a time zone offset (a character type in the format &#39;[+|-]TZH:TZM&#39;) or a time zone region name, depending on how the time zone value was specified when the database was created / last altered.
     * 
     */
    public Output<String> timeZone() {
        return this.timeZone;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ExternalContainerDatabase(String name) {
        this(name, ExternalContainerDatabaseArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ExternalContainerDatabase(String name, ExternalContainerDatabaseArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ExternalContainerDatabase(String name, ExternalContainerDatabaseArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/externalContainerDatabase:ExternalContainerDatabase", name, args == null ? ExternalContainerDatabaseArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private ExternalContainerDatabase(String name, Output<String> id, @Nullable ExternalContainerDatabaseState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/externalContainerDatabase:ExternalContainerDatabase", name, state, makeResourceOptions(options, id));
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
    public static ExternalContainerDatabase get(String name, Output<String> id, @Nullable ExternalContainerDatabaseState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ExternalContainerDatabase(name, id, state, options);
    }
}