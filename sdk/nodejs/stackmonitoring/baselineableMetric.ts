// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Baselineable Metric resource in Oracle Cloud Infrastructure Stack Monitoring service.
 *
 * Creates the specified Baseline-able metric
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBaselineableMetric = new oci.stackmonitoring.BaselineableMetric("testBaselineableMetric", {
 *     column: _var.baselineable_metric_column,
 *     compartmentId: _var.compartment_id,
 *     namespace: _var.baselineable_metric_namespace,
 *     resourceGroup: _var.baselineable_metric_resource_group,
 * });
 * ```
 *
 * ## Import
 *
 * BaselineableMetrics can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:StackMonitoring/baselineableMetric:BaselineableMetric test_baselineable_metric "id"
 * ```
 */
export class BaselineableMetric extends pulumi.CustomResource {
    /**
     * Get an existing BaselineableMetric resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: BaselineableMetricState, opts?: pulumi.CustomResourceOptions): BaselineableMetric {
        return new BaselineableMetric(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:StackMonitoring/baselineableMetric:BaselineableMetric';

    /**
     * Returns true if the given object is an instance of BaselineableMetric.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is BaselineableMetric {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === BaselineableMetric.__pulumiType;
    }

    /**
     * (Updatable) metric column name
     */
    public readonly column!: pulumi.Output<string>;
    /**
     * (Updatable) OCID of the compartment
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * Created user id
     */
    public /*out*/ readonly createdBy!: pulumi.Output<string>;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public /*out*/ readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public /*out*/ readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * Is the metric created out of box, default false
     */
    public /*out*/ readonly isOutOfBox!: pulumi.Output<boolean>;
    /**
     * last Updated user id
     */
    public /*out*/ readonly lastUpdatedBy!: pulumi.Output<string>;
    /**
     * (Updatable) name of the metric
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * (Updatable) namespace of the metric
     */
    public readonly namespace!: pulumi.Output<string>;
    /**
     * (Updatable) Resource group of the metric
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly resourceGroup!: pulumi.Output<string>;
    /**
     * The current lifecycle state of the metric extension
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * OCID of the tenancy
     */
    public /*out*/ readonly tenancyId!: pulumi.Output<string>;
    /**
     * creation date
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * last updated time
     */
    public /*out*/ readonly timeLastUpdated!: pulumi.Output<string>;

    /**
     * Create a BaselineableMetric resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: BaselineableMetricArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: BaselineableMetricArgs | BaselineableMetricState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as BaselineableMetricState | undefined;
            resourceInputs["column"] = state ? state.column : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["createdBy"] = state ? state.createdBy : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["isOutOfBox"] = state ? state.isOutOfBox : undefined;
            resourceInputs["lastUpdatedBy"] = state ? state.lastUpdatedBy : undefined;
            resourceInputs["name"] = state ? state.name : undefined;
            resourceInputs["namespace"] = state ? state.namespace : undefined;
            resourceInputs["resourceGroup"] = state ? state.resourceGroup : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["tenancyId"] = state ? state.tenancyId : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeLastUpdated"] = state ? state.timeLastUpdated : undefined;
        } else {
            const args = argsOrState as BaselineableMetricArgs | undefined;
            if ((!args || args.column === undefined) && !opts.urn) {
                throw new Error("Missing required property 'column'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.namespace === undefined) && !opts.urn) {
                throw new Error("Missing required property 'namespace'");
            }
            if ((!args || args.resourceGroup === undefined) && !opts.urn) {
                throw new Error("Missing required property 'resourceGroup'");
            }
            resourceInputs["column"] = args ? args.column : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["name"] = args ? args.name : undefined;
            resourceInputs["namespace"] = args ? args.namespace : undefined;
            resourceInputs["resourceGroup"] = args ? args.resourceGroup : undefined;
            resourceInputs["createdBy"] = undefined /*out*/;
            resourceInputs["definedTags"] = undefined /*out*/;
            resourceInputs["freeformTags"] = undefined /*out*/;
            resourceInputs["isOutOfBox"] = undefined /*out*/;
            resourceInputs["lastUpdatedBy"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["tenancyId"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeLastUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(BaselineableMetric.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering BaselineableMetric resources.
 */
export interface BaselineableMetricState {
    /**
     * (Updatable) metric column name
     */
    column?: pulumi.Input<string>;
    /**
     * (Updatable) OCID of the compartment
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * Created user id
     */
    createdBy?: pulumi.Input<string>;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * Is the metric created out of box, default false
     */
    isOutOfBox?: pulumi.Input<boolean>;
    /**
     * last Updated user id
     */
    lastUpdatedBy?: pulumi.Input<string>;
    /**
     * (Updatable) name of the metric
     */
    name?: pulumi.Input<string>;
    /**
     * (Updatable) namespace of the metric
     */
    namespace?: pulumi.Input<string>;
    /**
     * (Updatable) Resource group of the metric
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    resourceGroup?: pulumi.Input<string>;
    /**
     * The current lifecycle state of the metric extension
     */
    state?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * OCID of the tenancy
     */
    tenancyId?: pulumi.Input<string>;
    /**
     * creation date
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * last updated time
     */
    timeLastUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a BaselineableMetric resource.
 */
export interface BaselineableMetricArgs {
    /**
     * (Updatable) metric column name
     */
    column: pulumi.Input<string>;
    /**
     * (Updatable) OCID of the compartment
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) name of the metric
     */
    name?: pulumi.Input<string>;
    /**
     * (Updatable) namespace of the metric
     */
    namespace: pulumi.Input<string>;
    /**
     * (Updatable) Resource group of the metric
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    resourceGroup: pulumi.Input<string>;
}