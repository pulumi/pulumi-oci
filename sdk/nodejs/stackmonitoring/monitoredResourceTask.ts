// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Monitored Resource Task resource in Oracle Cloud Infrastructure Stack Monitoring service.
 *
 * Create a new stack monitoring resource task.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMonitoredResourceTask = new oci.stackmonitoring.MonitoredResourceTask("test_monitored_resource_task", {
 *     compartmentId: compartmentId,
 *     taskDetails: {
 *         type: monitoredResourceTaskTaskDetailsType,
 *         agentId: testAgent.id,
 *         availabilityProxyMetricCollectionInterval: monitoredResourceTaskTaskDetailsAvailabilityProxyMetricCollectionInterval,
 *         availabilityProxyMetrics: monitoredResourceTaskTaskDetailsAvailabilityProxyMetrics,
 *         consolePathPrefix: monitoredResourceTaskTaskDetailsConsolePathPrefix,
 *         externalIdMapping: monitoredResourceTaskTaskDetailsExternalIdMapping,
 *         handlerType: monitoredResourceTaskTaskDetailsHandlerType,
 *         isEnable: monitoredResourceTaskTaskDetailsIsEnable,
 *         lifecycleStatusMappingsForUpStatuses: monitoredResourceTaskTaskDetailsLifecycleStatusMappingsForUpStatus,
 *         namespace: monitoredResourceTaskTaskDetailsNamespace,
 *         receiverProperties: {
 *             listenerPort: monitoredResourceTaskTaskDetailsReceiverPropertiesListenerPort,
 *         },
 *         resourceGroup: monitoredResourceTaskTaskDetailsResourceGroup,
 *         resourceNameFilter: monitoredResourceTaskTaskDetailsResourceNameFilter,
 *         resourceNameMapping: monitoredResourceTaskTaskDetailsResourceNameMapping,
 *         resourceTypeFilter: monitoredResourceTaskTaskDetailsResourceTypeFilter,
 *         resourceTypeMapping: monitoredResourceTaskTaskDetailsResourceTypeMapping,
 *         resourceTypesConfigurations: [{
 *             availabilityMetricsConfig: {
 *                 collectionIntervalInSeconds: monitoredResourceTaskTaskDetailsResourceTypesConfigurationAvailabilityMetricsConfigCollectionIntervalInSeconds,
 *                 metrics: monitoredResourceTaskTaskDetailsResourceTypesConfigurationAvailabilityMetricsConfigMetrics,
 *             },
 *             handlerConfig: {
 *                 collectdResourceNameConfig: {
 *                     excludeProperties: monitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigCollectdResourceNameConfigExcludeProperties,
 *                     includeProperties: monitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigCollectdResourceNameConfigIncludeProperties,
 *                     suffix: monitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigCollectdResourceNameConfigSuffix,
 *                 },
 *                 collectorTypes: monitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigCollectorTypes,
 *                 handlerProperties: [{
 *                     name: monitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigHandlerPropertiesName,
 *                     value: monitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigHandlerPropertiesValue,
 *                 }],
 *                 metricMappings: [{
 *                     collectorMetricName: testMetric.name,
 *                     isSkipUpload: monitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigMetricMappingsIsSkipUpload,
 *                     metricUploadIntervalInSeconds: monitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigMetricMappingsMetricUploadIntervalInSeconds,
 *                     telemetryMetricName: testMetric.name,
 *                 }],
 *                 metricNameConfig: {
 *                     excludePatternOnPrefix: monitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigMetricNameConfigExcludePatternOnPrefix,
 *                     isPrefixWithCollectorType: monitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigMetricNameConfigIsPrefixWithCollectorType,
 *                 },
 *                 metricUploadIntervalInSeconds: monitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigMetricUploadIntervalInSeconds,
 *                 telegrafResourceNameConfig: {
 *                     excludeTags: monitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigTelegrafResourceNameConfigExcludeTags,
 *                     includeTags: monitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigTelegrafResourceNameConfigIncludeTags,
 *                     isUseTagsOnly: monitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigTelegrafResourceNameConfigIsUseTagsOnly,
 *                 },
 *                 telemetryResourceGroup: monitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigTelemetryResourceGroup,
 *             },
 *             resourceType: monitoredResourceTaskTaskDetailsResourceTypesConfigurationResourceType,
 *         }],
 *         serviceBaseUrl: monitoredResourceTaskTaskDetailsServiceBaseUrl,
 *         shouldUseMetricsFlowForStatus: monitoredResourceTaskTaskDetailsShouldUseMetricsFlowForStatus,
 *         source: monitoredResourceTaskTaskDetailsSource,
 *     },
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 *     name: monitoredResourceTaskName,
 * });
 * ```
 *
 * ## Import
 *
 * MonitoredResourceTasks can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:StackMonitoring/monitoredResourceTask:MonitoredResourceTask test_monitored_resource_task "id"
 * ```
 */
export class MonitoredResourceTask extends pulumi.CustomResource {
    /**
     * Get an existing MonitoredResourceTask resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: MonitoredResourceTaskState, opts?: pulumi.CustomResourceOptions): MonitoredResourceTask {
        return new MonitoredResourceTask(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:StackMonitoring/monitoredResourceTask:MonitoredResourceTask';

    /**
     * Returns true if the given object is an instance of MonitoredResourceTask.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is MonitoredResourceTask {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === MonitoredResourceTask.__pulumiType;
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment identifier.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * Name of the task. If not provided by default the following names will be taken Oracle Cloud Infrastructure tasks - namespace plus timestamp.
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * The current state of the stack monitoring resource task.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The request details for the performing the task.
     */
    public readonly taskDetails!: pulumi.Output<outputs.StackMonitoring.MonitoredResourceTaskTaskDetails>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy.
     */
    public /*out*/ readonly tenantId!: pulumi.Output<string>;
    /**
     * The date and time when the stack monitoring resource task was created, expressed in  [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time when the stack monitoring resource task was last updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * Type of the task.
     */
    public /*out*/ readonly type!: pulumi.Output<string>;
    /**
     * Identifiers [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for work requests submitted for this task.
     */
    public /*out*/ readonly workRequestIds!: pulumi.Output<string[]>;

    /**
     * Create a MonitoredResourceTask resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: MonitoredResourceTaskArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: MonitoredResourceTaskArgs | MonitoredResourceTaskState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as MonitoredResourceTaskState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["name"] = state ? state.name : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["taskDetails"] = state ? state.taskDetails : undefined;
            resourceInputs["tenantId"] = state ? state.tenantId : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["type"] = state ? state.type : undefined;
            resourceInputs["workRequestIds"] = state ? state.workRequestIds : undefined;
        } else {
            const args = argsOrState as MonitoredResourceTaskArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.taskDetails === undefined) && !opts.urn) {
                throw new Error("Missing required property 'taskDetails'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["name"] = args ? args.name : undefined;
            resourceInputs["taskDetails"] = args ? args.taskDetails : undefined;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["tenantId"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
            resourceInputs["type"] = undefined /*out*/;
            resourceInputs["workRequestIds"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(MonitoredResourceTask.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering MonitoredResourceTask resources.
 */
export interface MonitoredResourceTaskState {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment identifier.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Name of the task. If not provided by default the following names will be taken Oracle Cloud Infrastructure tasks - namespace plus timestamp.
     */
    name?: pulumi.Input<string>;
    /**
     * The current state of the stack monitoring resource task.
     */
    state?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The request details for the performing the task.
     */
    taskDetails?: pulumi.Input<inputs.StackMonitoring.MonitoredResourceTaskTaskDetails>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy.
     */
    tenantId?: pulumi.Input<string>;
    /**
     * The date and time when the stack monitoring resource task was created, expressed in  [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time when the stack monitoring resource task was last updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * Type of the task.
     */
    type?: pulumi.Input<string>;
    /**
     * Identifiers [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for work requests submitted for this task.
     */
    workRequestIds?: pulumi.Input<pulumi.Input<string>[]>;
}

/**
 * The set of arguments for constructing a MonitoredResourceTask resource.
 */
export interface MonitoredResourceTaskArgs {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment identifier.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Name of the task. If not provided by default the following names will be taken Oracle Cloud Infrastructure tasks - namespace plus timestamp.
     */
    name?: pulumi.Input<string>;
    /**
     * The request details for the performing the task.
     */
    taskDetails: pulumi.Input<inputs.StackMonitoring.MonitoredResourceTaskTaskDetails>;
}
