// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DisasterRecovery.DrPlanArgs;
import com.pulumi.oci.DisasterRecovery.inputs.DrPlanState;
import com.pulumi.oci.DisasterRecovery.outputs.DrPlanPlanGroup;
import com.pulumi.oci.Utilities;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Dr Plan resource in Oracle Cloud Infrastructure Disaster Recovery service.
 * 
 * Creates a new DR Plan of the specified DR Plan type.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.DisasterRecovery.DrPlan;
 * import com.pulumi.oci.DisasterRecovery.DrPlanArgs;
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
 *         var testDrPlan = new DrPlan(&#34;testDrPlan&#34;, DrPlanArgs.builder()        
 *             .displayName(var_.dr_plan_display_name())
 *             .drProtectionGroupId(oci_disaster_recovery_dr_protection_group.test_dr_protection_group().id())
 *             .type(var_.dr_plan_type())
 *             .definedTags(Map.of(&#34;Operations.CostCenter&#34;, &#34;42&#34;))
 *             .freeformTags(Map.of(&#34;Department&#34;, &#34;Finance&#34;))
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * DrPlans can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:DisasterRecovery/drPlan:DrPlan test_dr_plan &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:DisasterRecovery/drPlan:DrPlan")
public class DrPlan extends com.pulumi.resources.CustomResource {
    /**
     * The OCID of the compartment containing the DR Plan.  Example: `ocid1.compartment.oc1..exampleocid1`
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment containing the DR Plan.  Example: `ocid1.compartment.oc1..exampleocid1`
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) The display name of the DR Plan being created.  Example: `EBS Switchover PHX to IAD`
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) The display name of the DR Plan being created.  Example: `EBS Switchover PHX to IAD`
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * The OCID of the DR Protection Group to which this DR Plan belongs.  Example: `ocid1.drprotectiongroup.oc1.iad.exampleocid2`
     * 
     */
    @Export(name="drProtectionGroupId", type=String.class, parameters={})
    private Output<String> drProtectionGroupId;

    /**
     * @return The OCID of the DR Protection Group to which this DR Plan belongs.  Example: `ocid1.drprotectiongroup.oc1.iad.exampleocid2`
     * 
     */
    public Output<String> drProtectionGroupId() {
        return this.drProtectionGroupId;
    }
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * A message describing the DR Plan&#39;s current state in more detail.
     * 
     */
    @Export(name="lifeCycleDetails", type=String.class, parameters={})
    private Output<String> lifeCycleDetails;

    /**
     * @return A message describing the DR Plan&#39;s current state in more detail.
     * 
     */
    public Output<String> lifeCycleDetails() {
        return this.lifeCycleDetails;
    }
    /**
     * The OCID of the peer (remote) DR Protection Group associated with this plan&#39;s DR Protection Group.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid1`
     * 
     */
    @Export(name="peerDrProtectionGroupId", type=String.class, parameters={})
    private Output<String> peerDrProtectionGroupId;

    /**
     * @return The OCID of the peer (remote) DR Protection Group associated with this plan&#39;s DR Protection Group.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid1`
     * 
     */
    public Output<String> peerDrProtectionGroupId() {
        return this.peerDrProtectionGroupId;
    }
    /**
     * The region of the peer (remote) DR Protection Group associated with this plan&#39;s DR Protection Group.  Example: `us-phoenix-1`
     * 
     */
    @Export(name="peerRegion", type=String.class, parameters={})
    private Output<String> peerRegion;

    /**
     * @return The region of the peer (remote) DR Protection Group associated with this plan&#39;s DR Protection Group.  Example: `us-phoenix-1`
     * 
     */
    public Output<String> peerRegion() {
        return this.peerRegion;
    }
    /**
     * The list of groups in this DR Plan.
     * 
     */
    @Export(name="planGroups", type=List.class, parameters={DrPlanPlanGroup.class})
    private Output<List<DrPlanPlanGroup>> planGroups;

    /**
     * @return The list of groups in this DR Plan.
     * 
     */
    public Output<List<DrPlanPlanGroup>> planGroups() {
        return this.planGroups;
    }
    /**
     * The current state of the DR Plan.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the DR Plan.
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
     * The date and time the DR Plan was created. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the DR Plan was created. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The date and time the DR Plan was updated. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return The date and time the DR Plan was updated. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * The type of DR Plan to be created.
     * 
     */
    @Export(name="type", type=String.class, parameters={})
    private Output<String> type;

    /**
     * @return The type of DR Plan to be created.
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public DrPlan(String name) {
        this(name, DrPlanArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public DrPlan(String name, DrPlanArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public DrPlan(String name, DrPlanArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DisasterRecovery/drPlan:DrPlan", name, args == null ? DrPlanArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private DrPlan(String name, Output<String> id, @Nullable DrPlanState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DisasterRecovery/drPlan:DrPlan", name, state, makeResourceOptions(options, id));
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
    public static DrPlan get(String name, Output<String> id, @Nullable DrPlanState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new DrPlan(name, id, state, options);
    }
}