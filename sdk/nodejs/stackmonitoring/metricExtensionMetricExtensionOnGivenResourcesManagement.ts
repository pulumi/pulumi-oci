// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Metric Extension Metric Extension On Given Resources Management resource in Oracle Cloud Infrastructure Stack Monitoring service.
 *
 * Submits a request to enable matching metric extension Id for the given Resource IDs
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMetricExtensionMetricExtensionOnGivenResourcesManagement = new oci.stackmonitoring.MetricExtensionMetricExtensionOnGivenResourcesManagement("test_metric_extension_metric_extension_on_given_resources_management", {
 *     metricExtensionId: testMetricExtension.id,
 *     resourceIds: metricExtensionMetricExtensionOnGivenResourcesManagementResourceIds[0],
 *     enableMetricExtensionOnGivenResources: enableMetricExtensionOnGivenResources,
 * });
 * ```
 */
export class MetricExtensionMetricExtensionOnGivenResourcesManagement extends pulumi.CustomResource {
    /**
     * Get an existing MetricExtensionMetricExtensionOnGivenResourcesManagement resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: MetricExtensionMetricExtensionOnGivenResourcesManagementState, opts?: pulumi.CustomResourceOptions): MetricExtensionMetricExtensionOnGivenResourcesManagement {
        return new MetricExtensionMetricExtensionOnGivenResourcesManagement(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:StackMonitoring/metricExtensionMetricExtensionOnGivenResourcesManagement:MetricExtensionMetricExtensionOnGivenResourcesManagement';

    /**
     * Returns true if the given object is an instance of MetricExtensionMetricExtensionOnGivenResourcesManagement.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is MetricExtensionMetricExtensionOnGivenResourcesManagement {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === MetricExtensionMetricExtensionOnGivenResourcesManagement.__pulumiType;
    }

    /**
     * (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly enableMetricExtensionOnGivenResources!: pulumi.Output<boolean>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the metric extension resource.
     */
    public readonly metricExtensionId!: pulumi.Output<string>;
    /**
     * List of Resource IDs [OCIDs]. Currently, supports only one resource id per request.
     */
    public readonly resourceIds!: pulumi.Output<string>;

    /**
     * Create a MetricExtensionMetricExtensionOnGivenResourcesManagement resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: MetricExtensionMetricExtensionOnGivenResourcesManagementArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: MetricExtensionMetricExtensionOnGivenResourcesManagementArgs | MetricExtensionMetricExtensionOnGivenResourcesManagementState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as MetricExtensionMetricExtensionOnGivenResourcesManagementState | undefined;
            resourceInputs["enableMetricExtensionOnGivenResources"] = state ? state.enableMetricExtensionOnGivenResources : undefined;
            resourceInputs["metricExtensionId"] = state ? state.metricExtensionId : undefined;
            resourceInputs["resourceIds"] = state ? state.resourceIds : undefined;
        } else {
            const args = argsOrState as MetricExtensionMetricExtensionOnGivenResourcesManagementArgs | undefined;
            if ((!args || args.enableMetricExtensionOnGivenResources === undefined) && !opts.urn) {
                throw new Error("Missing required property 'enableMetricExtensionOnGivenResources'");
            }
            if ((!args || args.metricExtensionId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'metricExtensionId'");
            }
            if ((!args || args.resourceIds === undefined) && !opts.urn) {
                throw new Error("Missing required property 'resourceIds'");
            }
            resourceInputs["enableMetricExtensionOnGivenResources"] = args ? args.enableMetricExtensionOnGivenResources : undefined;
            resourceInputs["metricExtensionId"] = args ? args.metricExtensionId : undefined;
            resourceInputs["resourceIds"] = args ? args.resourceIds : undefined;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(MetricExtensionMetricExtensionOnGivenResourcesManagement.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering MetricExtensionMetricExtensionOnGivenResourcesManagement resources.
 */
export interface MetricExtensionMetricExtensionOnGivenResourcesManagementState {
    /**
     * (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    enableMetricExtensionOnGivenResources?: pulumi.Input<boolean>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the metric extension resource.
     */
    metricExtensionId?: pulumi.Input<string>;
    /**
     * List of Resource IDs [OCIDs]. Currently, supports only one resource id per request.
     */
    resourceIds?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a MetricExtensionMetricExtensionOnGivenResourcesManagement resource.
 */
export interface MetricExtensionMetricExtensionOnGivenResourcesManagementArgs {
    /**
     * (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    enableMetricExtensionOnGivenResources: pulumi.Input<boolean>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the metric extension resource.
     */
    metricExtensionId: pulumi.Input<string>;
    /**
     * List of Resource IDs [OCIDs]. Currently, supports only one resource id per request.
     */
    resourceIds: pulumi.Input<string>;
}
