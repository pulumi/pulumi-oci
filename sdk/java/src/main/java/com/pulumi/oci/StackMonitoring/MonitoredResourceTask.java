// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.StackMonitoring.MonitoredResourceTaskArgs;
import com.pulumi.oci.StackMonitoring.inputs.MonitoredResourceTaskState;
import com.pulumi.oci.StackMonitoring.outputs.MonitoredResourceTaskTaskDetails;
import com.pulumi.oci.Utilities;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Monitored Resource Task resource in Oracle Cloud Infrastructure Stack Monitoring service.
 * 
 * Create a new stack monitoring resource task.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.StackMonitoring.MonitoredResourceTask;
 * import com.pulumi.oci.StackMonitoring.MonitoredResourceTaskArgs;
 * import com.pulumi.oci.StackMonitoring.inputs.MonitoredResourceTaskTaskDetailsArgs;
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
 *         var testMonitoredResourceTask = new MonitoredResourceTask(&#34;testMonitoredResourceTask&#34;, MonitoredResourceTaskArgs.builder()        
 *             .compartmentId(var_.compartment_id())
 *             .taskDetails(MonitoredResourceTaskTaskDetailsArgs.builder()
 *                 .namespace(var_.monitored_resource_task_task_details_namespace())
 *                 .source(var_.monitored_resource_task_task_details_source())
 *                 .type(var_.monitored_resource_task_task_details_type())
 *                 .availabilityProxyMetricCollectionInterval(var_.monitored_resource_task_task_details_availability_proxy_metric_collection_interval())
 *                 .availabilityProxyMetrics(var_.monitored_resource_task_task_details_availability_proxy_metrics())
 *                 .resourceGroup(var_.monitored_resource_task_task_details_resource_group())
 *                 .build())
 *             .definedTags(Map.of(&#34;foo-namespace.bar-key&#34;, &#34;value&#34;))
 *             .freeformTags(Map.of(&#34;bar-key&#34;, &#34;value&#34;))
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * MonitoredResourceTasks can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:StackMonitoring/monitoredResourceTask:MonitoredResourceTask test_monitored_resource_task &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:StackMonitoring/monitoredResourceTask:MonitoredResourceTask")
public class MonitoredResourceTask extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment identifier.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment identifier.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class,Object.class}, tree="[0,1,2]")
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class,Object.class}, tree="[0,1,2]")
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * Name of the task. If not provided by default the following names will be taken Oracle Cloud Infrastructure tasks - namespace plus timestamp.
     * 
     */
    @Export(name="name", refs={String.class}, tree="[0]")
    private Output<String> name;

    /**
     * @return Name of the task. If not provided by default the following names will be taken Oracle Cloud Infrastructure tasks - namespace plus timestamp.
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * The current state of the stack monitoring resource task.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the stack monitoring resource task.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class,Object.class}, tree="[0,1,2]")
    private Output<Map<String,Object>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,Object>> systemTags() {
        return this.systemTags;
    }
    /**
     * The request details for the performing the task.
     * 
     */
    @Export(name="taskDetails", refs={MonitoredResourceTaskTaskDetails.class}, tree="[0]")
    private Output<MonitoredResourceTaskTaskDetails> taskDetails;

    /**
     * @return The request details for the performing the task.
     * 
     */
    public Output<MonitoredResourceTaskTaskDetails> taskDetails() {
        return this.taskDetails;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy.
     * 
     */
    @Export(name="tenantId", refs={String.class}, tree="[0]")
    private Output<String> tenantId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy.
     * 
     */
    public Output<String> tenantId() {
        return this.tenantId;
    }
    /**
     * The date and time when the stack monitoring resource task was created, expressed in  [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The date and time when the stack monitoring resource task was created, expressed in  [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The date and time when the stack monitoring resource task was last updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The date and time when the stack monitoring resource task was last updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * Identifiers [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for work requests submitted for this task.
     * 
     */
    @Export(name="workRequestIds", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> workRequestIds;

    /**
     * @return Identifiers [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for work requests submitted for this task.
     * 
     */
    public Output<List<String>> workRequestIds() {
        return this.workRequestIds;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public MonitoredResourceTask(String name) {
        this(name, MonitoredResourceTaskArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public MonitoredResourceTask(String name, MonitoredResourceTaskArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public MonitoredResourceTask(String name, MonitoredResourceTaskArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:StackMonitoring/monitoredResourceTask:MonitoredResourceTask", name, args == null ? MonitoredResourceTaskArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private MonitoredResourceTask(String name, Output<String> id, @Nullable MonitoredResourceTaskState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:StackMonitoring/monitoredResourceTask:MonitoredResourceTask", name, state, makeResourceOptions(options, id));
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
    public static MonitoredResourceTask get(String name, Output<String> id, @Nullable MonitoredResourceTaskState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new MonitoredResourceTask(name, id, state, options);
    }
}