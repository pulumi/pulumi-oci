// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Monitoring Template Alarm Condition resource in Oracle Cloud Infrastructure Stack Monitoring service.
 *
 * Create a new alarm condition in same monitoringTemplate compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMonitoringTemplateAlarmCondition = new oci.stackmonitoring.MonitoringTemplateAlarmCondition("test_monitoring_template_alarm_condition", {
 *     conditionType: monitoringTemplateAlarmConditionConditionType,
 *     conditions: [{
 *         query: monitoringTemplateAlarmConditionConditionsQuery,
 *         severity: monitoringTemplateAlarmConditionConditionsSeverity,
 *         body: monitoringTemplateAlarmConditionConditionsBody,
 *         shouldAppendNote: monitoringTemplateAlarmConditionConditionsShouldAppendNote,
 *         shouldAppendUrl: monitoringTemplateAlarmConditionConditionsShouldAppendUrl,
 *         triggerDelay: monitoringTemplateAlarmConditionConditionsTriggerDelay,
 *     }],
 *     metricName: testMetric.name,
 *     monitoringTemplateId: testMonitoringTemplate.id,
 *     namespace: monitoringTemplateAlarmConditionNamespace,
 *     resourceType: monitoringTemplateAlarmConditionResourceType,
 *     compositeType: monitoringTemplateAlarmConditionCompositeType,
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * MonitoringTemplateAlarmConditions can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:StackMonitoring/monitoringTemplateAlarmCondition:MonitoringTemplateAlarmCondition test_monitoring_template_alarm_condition "monitoringTemplates/{monitoringTemplateId}/alarmConditions/{alarmConditionId}"
 * ```
 */
export class MonitoringTemplateAlarmCondition extends pulumi.CustomResource {
    /**
     * Get an existing MonitoringTemplateAlarmCondition resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: MonitoringTemplateAlarmConditionState, opts?: pulumi.CustomResourceOptions): MonitoringTemplateAlarmCondition {
        return new MonitoringTemplateAlarmCondition(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:StackMonitoring/monitoringTemplateAlarmCondition:MonitoringTemplateAlarmCondition';

    /**
     * Returns true if the given object is an instance of MonitoringTemplateAlarmCondition.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is MonitoringTemplateAlarmCondition {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === MonitoringTemplateAlarmCondition.__pulumiType;
    }

    /**
     * (Updatable) The OCID of the composite resource type like EBS/PEOPLE_SOFT.
     */
    public readonly compositeType!: pulumi.Output<string>;
    /**
     * (Updatable) Type of defined monitoring template.
     */
    public readonly conditionType!: pulumi.Output<string>;
    /**
     * (Updatable) Monitoring template conditions.
     */
    public readonly conditions!: pulumi.Output<outputs.StackMonitoring.MonitoringTemplateAlarmConditionCondition[]>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) The metric name.
     */
    public readonly metricName!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
     */
    public readonly monitoringTemplateId!: pulumi.Output<string>;
    /**
     * (Updatable) The stack monitoring service or application emitting the metric that is evaluated by the alarm.
     */
    public readonly namespace!: pulumi.Output<string>;
    /**
     * (Updatable) The resource group OCID.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly resourceType!: pulumi.Output<string>;
    /**
     * The current lifecycle state of the monitoring template
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The current status of the monitoring template i.e. whether it is Published or Unpublished
     */
    public /*out*/ readonly status!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The date and time the alarm condition was created. Format defined by RFC3339.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the alarm condition was updated. Format defined by RFC3339.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a MonitoringTemplateAlarmCondition resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: MonitoringTemplateAlarmConditionArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: MonitoringTemplateAlarmConditionArgs | MonitoringTemplateAlarmConditionState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as MonitoringTemplateAlarmConditionState | undefined;
            resourceInputs["compositeType"] = state ? state.compositeType : undefined;
            resourceInputs["conditionType"] = state ? state.conditionType : undefined;
            resourceInputs["conditions"] = state ? state.conditions : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["metricName"] = state ? state.metricName : undefined;
            resourceInputs["monitoringTemplateId"] = state ? state.monitoringTemplateId : undefined;
            resourceInputs["namespace"] = state ? state.namespace : undefined;
            resourceInputs["resourceType"] = state ? state.resourceType : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["status"] = state ? state.status : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as MonitoringTemplateAlarmConditionArgs | undefined;
            if ((!args || args.conditionType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'conditionType'");
            }
            if ((!args || args.conditions === undefined) && !opts.urn) {
                throw new Error("Missing required property 'conditions'");
            }
            if ((!args || args.metricName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'metricName'");
            }
            if ((!args || args.monitoringTemplateId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'monitoringTemplateId'");
            }
            if ((!args || args.namespace === undefined) && !opts.urn) {
                throw new Error("Missing required property 'namespace'");
            }
            if ((!args || args.resourceType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'resourceType'");
            }
            resourceInputs["compositeType"] = args ? args.compositeType : undefined;
            resourceInputs["conditionType"] = args ? args.conditionType : undefined;
            resourceInputs["conditions"] = args ? args.conditions : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["metricName"] = args ? args.metricName : undefined;
            resourceInputs["monitoringTemplateId"] = args ? args.monitoringTemplateId : undefined;
            resourceInputs["namespace"] = args ? args.namespace : undefined;
            resourceInputs["resourceType"] = args ? args.resourceType : undefined;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["status"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(MonitoringTemplateAlarmCondition.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering MonitoringTemplateAlarmCondition resources.
 */
export interface MonitoringTemplateAlarmConditionState {
    /**
     * (Updatable) The OCID of the composite resource type like EBS/PEOPLE_SOFT.
     */
    compositeType?: pulumi.Input<string>;
    /**
     * (Updatable) Type of defined monitoring template.
     */
    conditionType?: pulumi.Input<string>;
    /**
     * (Updatable) Monitoring template conditions.
     */
    conditions?: pulumi.Input<pulumi.Input<inputs.StackMonitoring.MonitoringTemplateAlarmConditionCondition>[]>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The metric name.
     */
    metricName?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
     */
    monitoringTemplateId?: pulumi.Input<string>;
    /**
     * (Updatable) The stack monitoring service or application emitting the metric that is evaluated by the alarm.
     */
    namespace?: pulumi.Input<string>;
    /**
     * (Updatable) The resource group OCID.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    resourceType?: pulumi.Input<string>;
    /**
     * The current lifecycle state of the monitoring template
     */
    state?: pulumi.Input<string>;
    /**
     * The current status of the monitoring template i.e. whether it is Published or Unpublished
     */
    status?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The date and time the alarm condition was created. Format defined by RFC3339.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the alarm condition was updated. Format defined by RFC3339.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a MonitoringTemplateAlarmCondition resource.
 */
export interface MonitoringTemplateAlarmConditionArgs {
    /**
     * (Updatable) The OCID of the composite resource type like EBS/PEOPLE_SOFT.
     */
    compositeType?: pulumi.Input<string>;
    /**
     * (Updatable) Type of defined monitoring template.
     */
    conditionType: pulumi.Input<string>;
    /**
     * (Updatable) Monitoring template conditions.
     */
    conditions: pulumi.Input<pulumi.Input<inputs.StackMonitoring.MonitoringTemplateAlarmConditionCondition>[]>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The metric name.
     */
    metricName: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
     */
    monitoringTemplateId: pulumi.Input<string>;
    /**
     * (Updatable) The stack monitoring service or application emitting the metric that is evaluated by the alarm.
     */
    namespace: pulumi.Input<string>;
    /**
     * (Updatable) The resource group OCID.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    resourceType: pulumi.Input<string>;
}
