// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Opsi.ExadataInsightArgs;
import com.pulumi.oci.Opsi.inputs.ExadataInsightState;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Exadata Insight resource in Oracle Cloud Infrastructure Opsi service.
 * 
 * Create an Exadata insight resource for an Exadata system in Operations Insights. The Exadata system will be enabled in Operations Insights. Exadata-related metric collection and analysis will be started.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.Opsi.ExadataInsight;
 * import com.pulumi.oci.Opsi.ExadataInsightArgs;
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
 *         var testExadataInsight = new ExadataInsight(&#34;testExadataInsight&#34;, ExadataInsightArgs.builder()        
 *             .compartmentId(var_.compartment_id())
 *             .enterpriseManagerBridgeId(oci_opsi_enterprise_manager_bridge.test_enterprise_manager_bridge().id())
 *             .enterpriseManagerEntityIdentifier(var_.exadata_insight_enterprise_manager_entity_identifier())
 *             .enterpriseManagerIdentifier(var_.exadata_insight_enterprise_manager_identifier())
 *             .entitySource(var_.exadata_insight_entity_source())
 *             .definedTags(Map.of(&#34;foo-namespace.bar-key&#34;, &#34;value&#34;))
 *             .freeformTags(Map.of(&#34;bar-key&#34;, &#34;value&#34;))
 *             .isAutoSyncEnabled(var_.exadata_insight_is_auto_sync_enabled())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * ExadataInsights can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Opsi/exadataInsight:ExadataInsight test_exadata_insight &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Opsi/exadataInsight:ExadataInsight")
public class ExadataInsight extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) Compartment Identifier of Exadata insight
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment Identifier of Exadata insight
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
     * OPSI Enterprise Manager Bridge OCID
     * 
     */
    @Export(name="enterpriseManagerBridgeId", type=String.class, parameters={})
    private Output<String> enterpriseManagerBridgeId;

    /**
     * @return OPSI Enterprise Manager Bridge OCID
     * 
     */
    public Output<String> enterpriseManagerBridgeId() {
        return this.enterpriseManagerBridgeId;
    }
    /**
     * Enterprise Manager Entity Display Name
     * 
     */
    @Export(name="enterpriseManagerEntityDisplayName", type=String.class, parameters={})
    private Output<String> enterpriseManagerEntityDisplayName;

    /**
     * @return Enterprise Manager Entity Display Name
     * 
     */
    public Output<String> enterpriseManagerEntityDisplayName() {
        return this.enterpriseManagerEntityDisplayName;
    }
    /**
     * Enterprise Manager Entity Unique Identifier
     * 
     */
    @Export(name="enterpriseManagerEntityIdentifier", type=String.class, parameters={})
    private Output<String> enterpriseManagerEntityIdentifier;

    /**
     * @return Enterprise Manager Entity Unique Identifier
     * 
     */
    public Output<String> enterpriseManagerEntityIdentifier() {
        return this.enterpriseManagerEntityIdentifier;
    }
    /**
     * Enterprise Manager Entity Name
     * 
     */
    @Export(name="enterpriseManagerEntityName", type=String.class, parameters={})
    private Output<String> enterpriseManagerEntityName;

    /**
     * @return Enterprise Manager Entity Name
     * 
     */
    public Output<String> enterpriseManagerEntityName() {
        return this.enterpriseManagerEntityName;
    }
    /**
     * Enterprise Manager Entity Type
     * 
     */
    @Export(name="enterpriseManagerEntityType", type=String.class, parameters={})
    private Output<String> enterpriseManagerEntityType;

    /**
     * @return Enterprise Manager Entity Type
     * 
     */
    public Output<String> enterpriseManagerEntityType() {
        return this.enterpriseManagerEntityType;
    }
    /**
     * Enterprise Manager Unique Identifier
     * 
     */
    @Export(name="enterpriseManagerIdentifier", type=String.class, parameters={})
    private Output<String> enterpriseManagerIdentifier;

    /**
     * @return Enterprise Manager Unique Identifier
     * 
     */
    public Output<String> enterpriseManagerIdentifier() {
        return this.enterpriseManagerIdentifier;
    }
    /**
     * (Updatable) Source of the Exadata system.
     * 
     */
    @Export(name="entitySource", type=String.class, parameters={})
    private Output<String> entitySource;

    /**
     * @return (Updatable) Source of the Exadata system.
     * 
     */
    public Output<String> entitySource() {
        return this.entitySource;
    }
    /**
     * The user-friendly name for the Exadata system. The name does not have to be unique.
     * 
     */
    @Export(name="exadataDisplayName", type=String.class, parameters={})
    private Output<String> exadataDisplayName;

    /**
     * @return The user-friendly name for the Exadata system. The name does not have to be unique.
     * 
     */
    public Output<String> exadataDisplayName() {
        return this.exadataDisplayName;
    }
    /**
     * The Exadata system name. If the Exadata systems managed by Enterprise Manager, the name is unique amongst the Exadata systems managed by the same Enterprise Manager.
     * 
     */
    @Export(name="exadataName", type=String.class, parameters={})
    private Output<String> exadataName;

    /**
     * @return The Exadata system name. If the Exadata systems managed by Enterprise Manager, the name is unique amongst the Exadata systems managed by the same Enterprise Manager.
     * 
     */
    public Output<String> exadataName() {
        return this.exadataName;
    }
    /**
     * Exadata rack type.
     * 
     */
    @Export(name="exadataRackType", type=String.class, parameters={})
    private Output<String> exadataRackType;

    /**
     * @return Exadata rack type.
     * 
     */
    public Output<String> exadataRackType() {
        return this.exadataRackType;
    }
    /**
     * Operations Insights internal representation of the the Exadata system type.
     * 
     */
    @Export(name="exadataType", type=String.class, parameters={})
    private Output<String> exadataType;

    /**
     * @return Operations Insights internal representation of the the Exadata system type.
     * 
     */
    public Output<String> exadataType() {
        return this.exadataType;
    }
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * (Updatable) Set to true to enable automatic enablement and disablement of related targets from Enterprise Manager. New resources (e.g. Database Insights) will be placed in the same compartment as the related Exadata Insight.
     * 
     */
    @Export(name="isAutoSyncEnabled", type=Boolean.class, parameters={})
    private Output<Boolean> isAutoSyncEnabled;

    /**
     * @return (Updatable) Set to true to enable automatic enablement and disablement of related targets from Enterprise Manager. New resources (e.g. Database Insights) will be placed in the same compartment as the related Exadata Insight.
     * 
     */
    public Output<Boolean> isAutoSyncEnabled() {
        return this.isAutoSyncEnabled;
    }
    /**
     * true if virtualization is used in the Exadata system
     * 
     */
    @Export(name="isVirtualizedExadata", type=Boolean.class, parameters={})
    private Output<Boolean> isVirtualizedExadata;

    /**
     * @return true if virtualization is used in the Exadata system
     * 
     */
    public Output<Boolean> isVirtualizedExadata() {
        return this.isVirtualizedExadata;
    }
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    @Export(name="lifecycleDetails", type=String.class, parameters={})
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * The current state of the Exadata insight.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the Exadata insight.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * (Updatable) Status of the resource. Example: &#34;ENABLED&#34;, &#34;DISABLED&#34;. Resource can be either enabled or disabled by updating the value of status field to either &#34;ENABLED&#34; or &#34;DISABLED&#34;
     * 
     */
    @Export(name="status", type=String.class, parameters={})
    private Output<String> status;

    /**
     * @return (Updatable) Status of the resource. Example: &#34;ENABLED&#34;, &#34;DISABLED&#34;. Resource can be either enabled or disabled by updating the value of status field to either &#34;ENABLED&#34; or &#34;DISABLED&#34;
     * 
     */
    public Output<String> status() {
        return this.status;
    }
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,Object>> systemTags() {
        return this.systemTags;
    }
    /**
     * The time the the Exadata insight was first enabled. An RFC3339 formatted datetime string
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The time the the Exadata insight was first enabled. An RFC3339 formatted datetime string
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time the Exadata insight was updated. An RFC3339 formatted datetime string
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return The time the Exadata insight was updated. An RFC3339 formatted datetime string
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ExadataInsight(String name) {
        this(name, ExadataInsightArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ExadataInsight(String name, ExadataInsightArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ExadataInsight(String name, ExadataInsightArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Opsi/exadataInsight:ExadataInsight", name, args == null ? ExadataInsightArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private ExadataInsight(String name, Output<String> id, @Nullable ExadataInsightState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Opsi/exadataInsight:ExadataInsight", name, state, makeResourceOptions(options, id));
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
    public static ExadataInsight get(String name, Output<String> id, @Nullable ExadataInsightState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ExadataInsight(name, id, state, options);
    }
}