// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DataFlow.PoolArgs;
import com.pulumi.oci.DataFlow.inputs.PoolState;
import com.pulumi.oci.DataFlow.outputs.PoolConfiguration;
import com.pulumi.oci.DataFlow.outputs.PoolPoolMetric;
import com.pulumi.oci.DataFlow.outputs.PoolSchedule;
import com.pulumi.oci.Utilities;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Pool resource in Oracle Cloud Infrastructure Data Flow service.
 * 
 * Create a pool to be used by dataflow runs or applications.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.DataFlow.Pool;
 * import com.pulumi.oci.DataFlow.PoolArgs;
 * import com.pulumi.oci.DataFlow.inputs.PoolConfigurationArgs;
 * import com.pulumi.oci.DataFlow.inputs.PoolConfigurationShapeConfigArgs;
 * import com.pulumi.oci.DataFlow.inputs.PoolScheduleArgs;
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
 *         var testPool = new Pool(&#34;testPool&#34;, PoolArgs.builder()        
 *             .compartmentId(var_.compartment_id())
 *             .configurations(PoolConfigurationArgs.builder()
 *                 .max(var_.pool_configurations_max())
 *                 .min(var_.pool_configurations_min())
 *                 .shape(var_.pool_configurations_shape())
 *                 .shapeConfig(PoolConfigurationShapeConfigArgs.builder()
 *                     .memoryInGbs(var_.pool_configurations_shape_config_memory_in_gbs())
 *                     .ocpus(var_.pool_configurations_shape_config_ocpus())
 *                     .build())
 *                 .build())
 *             .displayName(var_.pool_display_name())
 *             .definedTags(Map.of(&#34;Operations.CostCenter&#34;, &#34;42&#34;))
 *             .description(var_.pool_description())
 *             .freeformTags(Map.of(&#34;Department&#34;, &#34;Finance&#34;))
 *             .idleTimeoutInMinutes(var_.pool_idle_timeout_in_minutes())
 *             .schedules(PoolScheduleArgs.builder()
 *                 .dayOfWeek(var_.pool_schedules_day_of_week())
 *                 .startTime(var_.pool_schedules_start_time())
 *                 .stopTime(var_.pool_schedules_stop_time())
 *                 .build())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * Pools can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:DataFlow/pool:Pool test_pool &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:DataFlow/pool:Pool")
public class Pool extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The OCID of a compartment.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of a compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) List of PoolConfig items.
     * 
     */
    @Export(name="configurations", type=List.class, parameters={PoolConfiguration.class})
    private Output<List<PoolConfiguration>> configurations;

    /**
     * @return (Updatable) List of PoolConfig items.
     * 
     */
    public Output<List<PoolConfiguration>> configurations() {
        return this.configurations;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) A user-friendly description. Avoid entering confidential information.
     * 
     */
    @Export(name="description", type=String.class, parameters={})
    private Output<String> description;

    /**
     * @return (Updatable) A user-friendly description. Avoid entering confidential information.
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) A user-friendly name. It does not have to be unique. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. It does not have to be unique. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * (Updatable) Optional timeout value in minutes used to auto stop Pools. A Pool will be auto stopped after inactivity for this amount of time period. If value not set, pool will not be auto stopped auto.
     * 
     */
    @Export(name="idleTimeoutInMinutes", type=Integer.class, parameters={})
    private Output<Integer> idleTimeoutInMinutes;

    /**
     * @return (Updatable) Optional timeout value in minutes used to auto stop Pools. A Pool will be auto stopped after inactivity for this amount of time period. If value not set, pool will not be auto stopped auto.
     * 
     */
    public Output<Integer> idleTimeoutInMinutes() {
        return this.idleTimeoutInMinutes;
    }
    /**
     * The detailed messages about the lifecycle state.
     * 
     */
    @Export(name="lifecycleDetails", type=String.class, parameters={})
    private Output<String> lifecycleDetails;

    /**
     * @return The detailed messages about the lifecycle state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * The OCID of the user who created the resource.
     * 
     */
    @Export(name="ownerPrincipalId", type=String.class, parameters={})
    private Output<String> ownerPrincipalId;

    /**
     * @return The OCID of the user who created the resource.
     * 
     */
    public Output<String> ownerPrincipalId() {
        return this.ownerPrincipalId;
    }
    /**
     * The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
     * 
     */
    @Export(name="ownerUserName", type=String.class, parameters={})
    private Output<String> ownerUserName;

    /**
     * @return The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
     * 
     */
    public Output<String> ownerUserName() {
        return this.ownerUserName;
    }
    /**
     * A collection of metrics related to a particular pool.
     * 
     */
    @Export(name="poolMetrics", type=List.class, parameters={PoolPoolMetric.class})
    private Output<List<PoolPoolMetric>> poolMetrics;

    /**
     * @return A collection of metrics related to a particular pool.
     * 
     */
    public Output<List<PoolPoolMetric>> poolMetrics() {
        return this.poolMetrics;
    }
    /**
     * (Updatable) A list of schedules for pool to auto start and stop.
     * 
     */
    @Export(name="schedules", type=List.class, parameters={PoolSchedule.class})
    private Output<List<PoolSchedule>> schedules;

    /**
     * @return (Updatable) A list of schedules for pool to auto start and stop.
     * 
     */
    public Output<List<PoolSchedule>> schedules() {
        return this.schedules;
    }
    /**
     * (Updatable) The target state for the Pool. Could be set to `ACTIVE` or `DELETED`.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return (Updatable) The target state for the Pool. Could be set to `ACTIVE` or `DELETED`.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The date and time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The date and time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return The date and time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Pool(String name) {
        this(name, PoolArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Pool(String name, PoolArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Pool(String name, PoolArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DataFlow/pool:Pool", name, args == null ? PoolArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private Pool(String name, Output<String> id, @Nullable PoolState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DataFlow/pool:Pool", name, state, makeResourceOptions(options, id));
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
    public static Pool get(String name, Output<String> id, @Nullable PoolState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Pool(name, id, state, options);
    }
}