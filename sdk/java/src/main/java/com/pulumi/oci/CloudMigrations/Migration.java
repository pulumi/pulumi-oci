// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.CloudMigrations.MigrationArgs;
import com.pulumi.oci.CloudMigrations.inputs.MigrationState;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Migration resource in Oracle Cloud Infrastructure Cloud Migrations service.
 * 
 * Creates a migration.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.CloudMigrations.Migration;
 * import com.pulumi.oci.CloudMigrations.MigrationArgs;
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
 *         var testMigration = new Migration(&#34;testMigration&#34;, MigrationArgs.builder()        
 *             .compartmentId(var_.compartment_id())
 *             .displayName(var_.migration_display_name())
 *             .definedTags(Map.of(&#34;foo-namespace.bar-key&#34;, &#34;value&#34;))
 *             .freeformTags(Map.of(&#34;bar-key&#34;, &#34;value&#34;))
 *             .isCompleted(var_.migration_is_completed())
 *             .replicationScheduleId(oci_cloud_migrations_replication_schedule.test_replication_schedule().id())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * Migrations can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:CloudMigrations/migration:Migration test_migration &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:CloudMigrations/migration:Migration")
public class Migration extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) Compartment identifier
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment identifier
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Migration identifier
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) Migration identifier
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * (Updatable) Indicates whether migration is marked as complete.
     * 
     */
    @Export(name="isCompleted", type=Boolean.class, parameters={})
    private Output<Boolean> isCompleted;

    /**
     * @return (Updatable) Indicates whether migration is marked as complete.
     * 
     */
    public Output<Boolean> isCompleted() {
        return this.isCompleted;
    }
    /**
     * A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
     * 
     */
    @Export(name="lifecycleDetails", type=String.class, parameters={})
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * (Updatable) Replication schedule identifier
     * 
     */
    @Export(name="replicationScheduleId", type=String.class, parameters={})
    private Output<String> replicationScheduleId;

    /**
     * @return (Updatable) Replication schedule identifier
     * 
     */
    public Output<String> replicationScheduleId() {
        return this.replicationScheduleId;
    }
    /**
     * The current state of migration.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of migration.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,Object>> systemTags() {
        return this.systemTags;
    }
    /**
     * The time when the migration project was created. An RFC3339 formatted datetime string
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The time when the migration project was created. An RFC3339 formatted datetime string
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time when the migration project was updated. An RFC3339 formatted datetime string
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return The time when the migration project was updated. An RFC3339 formatted datetime string
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Migration(String name) {
        this(name, MigrationArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Migration(String name, MigrationArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Migration(String name, MigrationArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:CloudMigrations/migration:Migration", name, args == null ? MigrationArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private Migration(String name, Output<String> id, @Nullable MigrationState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:CloudMigrations/migration:Migration", name, state, makeResourceOptions(options, id));
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
    public static Migration get(String name, Output<String> id, @Nullable MigrationState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Migration(name, id, state, options);
    }
}