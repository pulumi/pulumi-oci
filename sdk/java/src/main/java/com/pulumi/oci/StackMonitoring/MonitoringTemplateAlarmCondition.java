// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.StackMonitoring.MonitoringTemplateAlarmConditionArgs;
import com.pulumi.oci.StackMonitoring.inputs.MonitoringTemplateAlarmConditionState;
import com.pulumi.oci.StackMonitoring.outputs.MonitoringTemplateAlarmConditionCondition;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Monitoring Template Alarm Condition resource in Oracle Cloud Infrastructure Stack Monitoring service.
 * 
 * Create a new alarm condition in same monitoringTemplate compartment.
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
 * import com.pulumi.oci.StackMonitoring.MonitoringTemplateAlarmCondition;
 * import com.pulumi.oci.StackMonitoring.MonitoringTemplateAlarmConditionArgs;
 * import com.pulumi.oci.StackMonitoring.inputs.MonitoringTemplateAlarmConditionConditionArgs;
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
 *         var testMonitoringTemplateAlarmCondition = new MonitoringTemplateAlarmCondition("testMonitoringTemplateAlarmCondition", MonitoringTemplateAlarmConditionArgs.builder()
 *             .conditionType(monitoringTemplateAlarmConditionConditionType)
 *             .conditions(MonitoringTemplateAlarmConditionConditionArgs.builder()
 *                 .query(monitoringTemplateAlarmConditionConditionsQuery)
 *                 .severity(monitoringTemplateAlarmConditionConditionsSeverity)
 *                 .body(monitoringTemplateAlarmConditionConditionsBody)
 *                 .shouldAppendNote(monitoringTemplateAlarmConditionConditionsShouldAppendNote)
 *                 .shouldAppendUrl(monitoringTemplateAlarmConditionConditionsShouldAppendUrl)
 *                 .triggerDelay(monitoringTemplateAlarmConditionConditionsTriggerDelay)
 *                 .build())
 *             .metricName(testMetric.name())
 *             .monitoringTemplateId(testMonitoringTemplate.id())
 *             .namespace(monitoringTemplateAlarmConditionNamespace)
 *             .resourceType(monitoringTemplateAlarmConditionResourceType)
 *             .compositeType(monitoringTemplateAlarmConditionCompositeType)
 *             .definedTags(Map.of("foo-namespace.bar-key", "value"))
 *             .freeformTags(Map.of("bar-key", "value"))
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
 * MonitoringTemplateAlarmConditions can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:StackMonitoring/monitoringTemplateAlarmCondition:MonitoringTemplateAlarmCondition test_monitoring_template_alarm_condition &#34;monitoringTemplates/{monitoringTemplateId}/alarmConditions/{alarmConditionId}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:StackMonitoring/monitoringTemplateAlarmCondition:MonitoringTemplateAlarmCondition")
public class MonitoringTemplateAlarmCondition extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The OCID of the composite resource type like EBS/PEOPLE_SOFT.
     * 
     */
    @Export(name="compositeType", refs={String.class}, tree="[0]")
    private Output<String> compositeType;

    /**
     * @return (Updatable) The OCID of the composite resource type like EBS/PEOPLE_SOFT.
     * 
     */
    public Output<String> compositeType() {
        return this.compositeType;
    }
    /**
     * (Updatable) Type of defined monitoring template.
     * 
     */
    @Export(name="conditionType", refs={String.class}, tree="[0]")
    private Output<String> conditionType;

    /**
     * @return (Updatable) Type of defined monitoring template.
     * 
     */
    public Output<String> conditionType() {
        return this.conditionType;
    }
    /**
     * (Updatable) Monitoring template conditions.
     * 
     */
    @Export(name="conditions", refs={List.class,MonitoringTemplateAlarmConditionCondition.class}, tree="[0,1]")
    private Output<List<MonitoringTemplateAlarmConditionCondition>> conditions;

    /**
     * @return (Updatable) Monitoring template conditions.
     * 
     */
    public Output<List<MonitoringTemplateAlarmConditionCondition>> conditions() {
        return this.conditions;
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
     * (Updatable) The metric name.
     * 
     */
    @Export(name="metricName", refs={String.class}, tree="[0]")
    private Output<String> metricName;

    /**
     * @return (Updatable) The metric name.
     * 
     */
    public Output<String> metricName() {
        return this.metricName;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
     * 
     */
    @Export(name="monitoringTemplateId", refs={String.class}, tree="[0]")
    private Output<String> monitoringTemplateId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
     * 
     */
    public Output<String> monitoringTemplateId() {
        return this.monitoringTemplateId;
    }
    /**
     * (Updatable) The stack monitoring service or application emitting the metric that is evaluated by the alarm.
     * 
     */
    @Export(name="namespace", refs={String.class}, tree="[0]")
    private Output<String> namespace;

    /**
     * @return (Updatable) The stack monitoring service or application emitting the metric that is evaluated by the alarm.
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }
    /**
     * (Updatable) The resource group OCID.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="resourceType", refs={String.class}, tree="[0]")
    private Output<String> resourceType;

    /**
     * @return (Updatable) The resource group OCID.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> resourceType() {
        return this.resourceType;
    }
    /**
     * The current lifecycle state of the monitoring template
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current lifecycle state of the monitoring template
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The current status of the monitoring template i.e. whether it is Published or Unpublished
     * 
     */
    @Export(name="status", refs={String.class}, tree="[0]")
    private Output<String> status;

    /**
     * @return The current status of the monitoring template i.e. whether it is Published or Unpublished
     * 
     */
    public Output<String> status() {
        return this.status;
    }
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,String>> systemTags() {
        return this.systemTags;
    }
    /**
     * The date and time the alarm condition was created. Format defined by RFC3339.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The date and time the alarm condition was created. Format defined by RFC3339.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The date and time the alarm condition was updated. Format defined by RFC3339.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The date and time the alarm condition was updated. Format defined by RFC3339.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public MonitoringTemplateAlarmCondition(java.lang.String name) {
        this(name, MonitoringTemplateAlarmConditionArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public MonitoringTemplateAlarmCondition(java.lang.String name, MonitoringTemplateAlarmConditionArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public MonitoringTemplateAlarmCondition(java.lang.String name, MonitoringTemplateAlarmConditionArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:StackMonitoring/monitoringTemplateAlarmCondition:MonitoringTemplateAlarmCondition", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private MonitoringTemplateAlarmCondition(java.lang.String name, Output<java.lang.String> id, @Nullable MonitoringTemplateAlarmConditionState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:StackMonitoring/monitoringTemplateAlarmCondition:MonitoringTemplateAlarmCondition", name, state, makeResourceOptions(options, id), false);
    }

    private static MonitoringTemplateAlarmConditionArgs makeArgs(MonitoringTemplateAlarmConditionArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? MonitoringTemplateAlarmConditionArgs.Empty : args;
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
    public static MonitoringTemplateAlarmCondition get(java.lang.String name, Output<java.lang.String> id, @Nullable MonitoringTemplateAlarmConditionState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new MonitoringTemplateAlarmCondition(name, id, state, options);
    }
}
