// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.CloudMigrations.MigrationPlanArgs;
import com.pulumi.oci.CloudMigrations.inputs.MigrationPlanState;
import com.pulumi.oci.CloudMigrations.outputs.MigrationPlanMigrationPlanStat;
import com.pulumi.oci.CloudMigrations.outputs.MigrationPlanStrategy;
import com.pulumi.oci.CloudMigrations.outputs.MigrationPlanTargetEnvironment;
import com.pulumi.oci.Utilities;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Migration Plan resource in Oracle Cloud Infrastructure Cloud Migrations service.
 * 
 * Creates a migration plan.
 * 
 * ## Import
 * 
 * MigrationPlans can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:CloudMigrations/migrationPlan:MigrationPlan test_migration_plan &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:CloudMigrations/migrationPlan:MigrationPlan")
public class MigrationPlan extends com.pulumi.resources.CustomResource {
    /**
     * Limits of the resources that are needed for migration. Example: {&#34;BlockVolume&#34;: 2, &#34;VCN&#34;: 1}
     * 
     */
    @Export(name="calculatedLimits", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> calculatedLimits;

    /**
     * @return Limits of the resources that are needed for migration. Example: {&#34;BlockVolume&#34;: 2, &#34;VCN&#34;: 1}
     * 
     */
    public Output<Map<String,Object>> calculatedLimits() {
        return this.calculatedLimits;
    }
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
     * (Updatable) Migration plan identifier
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) Migration plan identifier
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
     * The OCID of the associated migration.
     * 
     */
    @Export(name="migrationId", type=String.class, parameters={})
    private Output<String> migrationId;

    /**
     * @return The OCID of the associated migration.
     * 
     */
    public Output<String> migrationId() {
        return this.migrationId;
    }
    /**
     * Status of the migration plan.
     * 
     */
    @Export(name="migrationPlanStats", type=List.class, parameters={MigrationPlanMigrationPlanStat.class})
    private Output<List<MigrationPlanMigrationPlanStat>> migrationPlanStats;

    /**
     * @return Status of the migration plan.
     * 
     */
    public Output<List<MigrationPlanMigrationPlanStat>> migrationPlanStats() {
        return this.migrationPlanStats;
    }
    /**
     * OCID of the referenced ORM job.
     * 
     */
    @Export(name="referenceToRmsStack", type=String.class, parameters={})
    private Output<String> referenceToRmsStack;

    /**
     * @return OCID of the referenced ORM job.
     * 
     */
    public Output<String> referenceToRmsStack() {
        return this.referenceToRmsStack;
    }
    /**
     * Source migraiton plan ID to be cloned.
     * 
     */
    @Export(name="sourceMigrationPlanId", type=String.class, parameters={})
    private Output<String> sourceMigrationPlanId;

    /**
     * @return Source migraiton plan ID to be cloned.
     * 
     */
    public Output<String> sourceMigrationPlanId() {
        return this.sourceMigrationPlanId;
    }
    /**
     * The current state of the migration plan.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the migration plan.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * (Updatable) List of strategies for the resources to be migrated.
     * 
     */
    @Export(name="strategies", type=List.class, parameters={MigrationPlanStrategy.class})
    private Output<List<MigrationPlanStrategy>> strategies;

    /**
     * @return (Updatable) List of strategies for the resources to be migrated.
     * 
     */
    public Output<List<MigrationPlanStrategy>> strategies() {
        return this.strategies;
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
     * (Updatable) List of target environments.
     * 
     */
    @Export(name="targetEnvironments", type=List.class, parameters={MigrationPlanTargetEnvironment.class})
    private Output<List<MigrationPlanTargetEnvironment>> targetEnvironments;

    /**
     * @return (Updatable) List of target environments.
     * 
     */
    public Output<List<MigrationPlanTargetEnvironment>> targetEnvironments() {
        return this.targetEnvironments;
    }
    /**
     * The time when the migration plan was created. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The time when the migration plan was created. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time when the migration plan was updated. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return The time when the migration plan was updated. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public MigrationPlan(String name) {
        this(name, MigrationPlanArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public MigrationPlan(String name, MigrationPlanArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public MigrationPlan(String name, MigrationPlanArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:CloudMigrations/migrationPlan:MigrationPlan", name, args == null ? MigrationPlanArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private MigrationPlan(String name, Output<String> id, @Nullable MigrationPlanState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:CloudMigrations/migrationPlan:MigrationPlan", name, state, makeResourceOptions(options, id));
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
    public static MigrationPlan get(String name, Output<String> id, @Nullable MigrationPlanState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new MigrationPlan(name, id, state, options);
    }
}