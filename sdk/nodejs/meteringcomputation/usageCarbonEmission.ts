// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Usage Carbon Emission resource in Oracle Cloud Infrastructure Metering Computation service.
 *
 * Returns carbon emission usage for the given account.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testUsageCarbonEmission = new oci.meteringcomputation.UsageCarbonEmission("test_usage_carbon_emission", {
 *     tenantId: testTenant.id,
 *     timeUsageEnded: usageCarbonEmissionTimeUsageEnded,
 *     timeUsageStarted: usageCarbonEmissionTimeUsageStarted,
 *     compartmentDepth: usageCarbonEmissionCompartmentDepth,
 *     emissionCalculationMethod: usageCarbonEmissionEmissionCalculationMethod,
 *     emissionType: usageCarbonEmissionEmissionType,
 *     granularity: usageCarbonEmissionGranularity,
 *     groupBies: usageCarbonEmissionGroupBy,
 *     groupByTags: [{
 *         key: usageCarbonEmissionGroupByTagKey,
 *         namespace: usageCarbonEmissionGroupByTagNamespace,
 *         value: usageCarbonEmissionGroupByTagValue,
 *     }],
 *     isAggregateByTime: usageCarbonEmissionIsAggregateByTime,
 *     usageCarbonEmissionFilter: usageCarbonEmissionUsageCarbonEmissionFilter,
 * });
 * ```
 *
 * ## Import
 *
 * UsageCarbonEmissions can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:MeteringComputation/usageCarbonEmission:UsageCarbonEmission test_usage_carbon_emission "id"
 * ```
 */
export class UsageCarbonEmission extends pulumi.CustomResource {
    /**
     * Get an existing UsageCarbonEmission resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: UsageCarbonEmissionState, opts?: pulumi.CustomResourceOptions): UsageCarbonEmission {
        return new UsageCarbonEmission(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:MeteringComputation/usageCarbonEmission:UsageCarbonEmission';

    /**
     * Returns true if the given object is an instance of UsageCarbonEmission.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is UsageCarbonEmission {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === UsageCarbonEmission.__pulumiType;
    }

    /**
     * The compartment depth level.
     */
    public readonly compartmentDepth!: pulumi.Output<number>;
    /**
     * Specifies the method used for emission calculation, such as POWER_BASED or SPEND_BASED
     */
    public readonly emissionCalculationMethod!: pulumi.Output<string>;
    /**
     * Specifies the type of emission, such as MARKET_BASED or LOCATION_BASED.
     */
    public readonly emissionType!: pulumi.Output<string>;
    /**
     * The carbon emission granularity. DAILY - Daily data aggregation. MONTHLY - Monthly data aggregation.
     */
    public readonly granularity!: pulumi.Output<string>;
    /**
     * Aggregate the result by. For example: `["tagNamespace", "tagKey", "tagValue", "service", "skuName", "skuPartNumber", "unit", "compartmentName", "compartmentPath", "compartmentId", "platform", "region", "logicalAd", "resourceId", "resourceName", "tenantId", "tenantName", "subscriptionId"]`
     */
    public readonly groupBies!: pulumi.Output<string[]>;
    /**
     * GroupBy a specific tagKey. Provide the tagNamespace and tagKey in the tag object. Only supports one tag in the list. For example: `[{"namespace":"oracle", "key":"createdBy"]`
     */
    public readonly groupByTags!: pulumi.Output<outputs.MeteringComputation.UsageCarbonEmissionGroupByTag[]>;
    /**
     * Specifies whether aggregated by time. If isAggregateByTime is true, all carbon emissions usage over the query time period are summed.
     */
    public readonly isAggregateByTime!: pulumi.Output<boolean>;
    /**
     * A list of carbon emission usage items.
     */
    public /*out*/ readonly items!: pulumi.Output<outputs.MeteringComputation.UsageCarbonEmissionItem[]>;
    /**
     * Tenant ID.
     */
    public readonly tenantId!: pulumi.Output<string>;
    /**
     * The usage end time.
     */
    public readonly timeUsageEnded!: pulumi.Output<string>;
    /**
     * The usage start time.
     */
    public readonly timeUsageStarted!: pulumi.Output<string>;
    /**
     * The filter object for query usage.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly usageCarbonEmissionFilter!: pulumi.Output<string>;

    /**
     * Create a UsageCarbonEmission resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: UsageCarbonEmissionArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: UsageCarbonEmissionArgs | UsageCarbonEmissionState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as UsageCarbonEmissionState | undefined;
            resourceInputs["compartmentDepth"] = state ? state.compartmentDepth : undefined;
            resourceInputs["emissionCalculationMethod"] = state ? state.emissionCalculationMethod : undefined;
            resourceInputs["emissionType"] = state ? state.emissionType : undefined;
            resourceInputs["granularity"] = state ? state.granularity : undefined;
            resourceInputs["groupBies"] = state ? state.groupBies : undefined;
            resourceInputs["groupByTags"] = state ? state.groupByTags : undefined;
            resourceInputs["isAggregateByTime"] = state ? state.isAggregateByTime : undefined;
            resourceInputs["items"] = state ? state.items : undefined;
            resourceInputs["tenantId"] = state ? state.tenantId : undefined;
            resourceInputs["timeUsageEnded"] = state ? state.timeUsageEnded : undefined;
            resourceInputs["timeUsageStarted"] = state ? state.timeUsageStarted : undefined;
            resourceInputs["usageCarbonEmissionFilter"] = state ? state.usageCarbonEmissionFilter : undefined;
        } else {
            const args = argsOrState as UsageCarbonEmissionArgs | undefined;
            if ((!args || args.tenantId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'tenantId'");
            }
            if ((!args || args.timeUsageEnded === undefined) && !opts.urn) {
                throw new Error("Missing required property 'timeUsageEnded'");
            }
            if ((!args || args.timeUsageStarted === undefined) && !opts.urn) {
                throw new Error("Missing required property 'timeUsageStarted'");
            }
            resourceInputs["compartmentDepth"] = args ? args.compartmentDepth : undefined;
            resourceInputs["emissionCalculationMethod"] = args ? args.emissionCalculationMethod : undefined;
            resourceInputs["emissionType"] = args ? args.emissionType : undefined;
            resourceInputs["granularity"] = args ? args.granularity : undefined;
            resourceInputs["groupBies"] = args ? args.groupBies : undefined;
            resourceInputs["groupByTags"] = args ? args.groupByTags : undefined;
            resourceInputs["isAggregateByTime"] = args ? args.isAggregateByTime : undefined;
            resourceInputs["tenantId"] = args ? args.tenantId : undefined;
            resourceInputs["timeUsageEnded"] = args ? args.timeUsageEnded : undefined;
            resourceInputs["timeUsageStarted"] = args ? args.timeUsageStarted : undefined;
            resourceInputs["usageCarbonEmissionFilter"] = args ? args.usageCarbonEmissionFilter : undefined;
            resourceInputs["items"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(UsageCarbonEmission.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering UsageCarbonEmission resources.
 */
export interface UsageCarbonEmissionState {
    /**
     * The compartment depth level.
     */
    compartmentDepth?: pulumi.Input<number>;
    /**
     * Specifies the method used for emission calculation, such as POWER_BASED or SPEND_BASED
     */
    emissionCalculationMethod?: pulumi.Input<string>;
    /**
     * Specifies the type of emission, such as MARKET_BASED or LOCATION_BASED.
     */
    emissionType?: pulumi.Input<string>;
    /**
     * The carbon emission granularity. DAILY - Daily data aggregation. MONTHLY - Monthly data aggregation.
     */
    granularity?: pulumi.Input<string>;
    /**
     * Aggregate the result by. For example: `["tagNamespace", "tagKey", "tagValue", "service", "skuName", "skuPartNumber", "unit", "compartmentName", "compartmentPath", "compartmentId", "platform", "region", "logicalAd", "resourceId", "resourceName", "tenantId", "tenantName", "subscriptionId"]`
     */
    groupBies?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * GroupBy a specific tagKey. Provide the tagNamespace and tagKey in the tag object. Only supports one tag in the list. For example: `[{"namespace":"oracle", "key":"createdBy"]`
     */
    groupByTags?: pulumi.Input<pulumi.Input<inputs.MeteringComputation.UsageCarbonEmissionGroupByTag>[]>;
    /**
     * Specifies whether aggregated by time. If isAggregateByTime is true, all carbon emissions usage over the query time period are summed.
     */
    isAggregateByTime?: pulumi.Input<boolean>;
    /**
     * A list of carbon emission usage items.
     */
    items?: pulumi.Input<pulumi.Input<inputs.MeteringComputation.UsageCarbonEmissionItem>[]>;
    /**
     * Tenant ID.
     */
    tenantId?: pulumi.Input<string>;
    /**
     * The usage end time.
     */
    timeUsageEnded?: pulumi.Input<string>;
    /**
     * The usage start time.
     */
    timeUsageStarted?: pulumi.Input<string>;
    /**
     * The filter object for query usage.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    usageCarbonEmissionFilter?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a UsageCarbonEmission resource.
 */
export interface UsageCarbonEmissionArgs {
    /**
     * The compartment depth level.
     */
    compartmentDepth?: pulumi.Input<number>;
    /**
     * Specifies the method used for emission calculation, such as POWER_BASED or SPEND_BASED
     */
    emissionCalculationMethod?: pulumi.Input<string>;
    /**
     * Specifies the type of emission, such as MARKET_BASED or LOCATION_BASED.
     */
    emissionType?: pulumi.Input<string>;
    /**
     * The carbon emission granularity. DAILY - Daily data aggregation. MONTHLY - Monthly data aggregation.
     */
    granularity?: pulumi.Input<string>;
    /**
     * Aggregate the result by. For example: `["tagNamespace", "tagKey", "tagValue", "service", "skuName", "skuPartNumber", "unit", "compartmentName", "compartmentPath", "compartmentId", "platform", "region", "logicalAd", "resourceId", "resourceName", "tenantId", "tenantName", "subscriptionId"]`
     */
    groupBies?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * GroupBy a specific tagKey. Provide the tagNamespace and tagKey in the tag object. Only supports one tag in the list. For example: `[{"namespace":"oracle", "key":"createdBy"]`
     */
    groupByTags?: pulumi.Input<pulumi.Input<inputs.MeteringComputation.UsageCarbonEmissionGroupByTag>[]>;
    /**
     * Specifies whether aggregated by time. If isAggregateByTime is true, all carbon emissions usage over the query time period are summed.
     */
    isAggregateByTime?: pulumi.Input<boolean>;
    /**
     * Tenant ID.
     */
    tenantId: pulumi.Input<string>;
    /**
     * The usage end time.
     */
    timeUsageEnded: pulumi.Input<string>;
    /**
     * The usage start time.
     */
    timeUsageStarted: pulumi.Input<string>;
    /**
     * The filter object for query usage.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    usageCarbonEmissionFilter?: pulumi.Input<string>;
}
