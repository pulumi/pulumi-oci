// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Capture Filter resource in Oracle Cloud Infrastructure Core service.
 *
 * Creates a virtual test access point (VTAP) capture filter in the specified compartment.
 *
 * For the purposes of access control, you must provide the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains
 * the VTAP. For more information about compartments and access control, see
 * [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
 * For information about OCIDs, see [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
 *
 * You may optionally specify a *display name* for the VTAP, otherwise a default is provided.
 * It does not have to be unique, and you can change it.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCaptureFilter = new oci.core.CaptureFilter("test_capture_filter", {
 *     compartmentId: compartmentId,
 *     filterType: captureFilterFilterType,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     displayName: captureFilterDisplayName,
 *     flowLogCaptureFilterRules: [{
 *         destinationCidr: captureFilterFlowLogCaptureFilterRulesDestinationCidr,
 *         flowLogType: captureFilterFlowLogCaptureFilterRulesFlowLogType,
 *         icmpOptions: {
 *             type: captureFilterFlowLogCaptureFilterRulesIcmpOptionsType,
 *             code: captureFilterFlowLogCaptureFilterRulesIcmpOptionsCode,
 *         },
 *         isEnabled: captureFilterFlowLogCaptureFilterRulesIsEnabled,
 *         priority: captureFilterFlowLogCaptureFilterRulesPriority,
 *         protocol: captureFilterFlowLogCaptureFilterRulesProtocol,
 *         ruleAction: captureFilterFlowLogCaptureFilterRulesRuleAction,
 *         samplingRate: captureFilterFlowLogCaptureFilterRulesSamplingRate,
 *         sourceCidr: captureFilterFlowLogCaptureFilterRulesSourceCidr,
 *         tcpOptions: {
 *             destinationPortRange: {
 *                 max: captureFilterFlowLogCaptureFilterRulesTcpOptionsDestinationPortRangeMax,
 *                 min: captureFilterFlowLogCaptureFilterRulesTcpOptionsDestinationPortRangeMin,
 *             },
 *             sourcePortRange: {
 *                 max: captureFilterFlowLogCaptureFilterRulesTcpOptionsSourcePortRangeMax,
 *                 min: captureFilterFlowLogCaptureFilterRulesTcpOptionsSourcePortRangeMin,
 *             },
 *         },
 *         udpOptions: {
 *             destinationPortRange: {
 *                 max: captureFilterFlowLogCaptureFilterRulesUdpOptionsDestinationPortRangeMax,
 *                 min: captureFilterFlowLogCaptureFilterRulesUdpOptionsDestinationPortRangeMin,
 *             },
 *             sourcePortRange: {
 *                 max: captureFilterFlowLogCaptureFilterRulesUdpOptionsSourcePortRangeMax,
 *                 min: captureFilterFlowLogCaptureFilterRulesUdpOptionsSourcePortRangeMin,
 *             },
 *         },
 *     }],
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     vtapCaptureFilterRules: [{
 *         trafficDirection: captureFilterVtapCaptureFilterRulesTrafficDirection,
 *         destinationCidr: captureFilterVtapCaptureFilterRulesDestinationCidr,
 *         icmpOptions: {
 *             type: captureFilterVtapCaptureFilterRulesIcmpOptionsType,
 *             code: captureFilterVtapCaptureFilterRulesIcmpOptionsCode,
 *         },
 *         protocol: captureFilterVtapCaptureFilterRulesProtocol,
 *         ruleAction: captureFilterVtapCaptureFilterRulesRuleAction,
 *         sourceCidr: captureFilterVtapCaptureFilterRulesSourceCidr,
 *         tcpOptions: {
 *             destinationPortRange: {
 *                 max: captureFilterVtapCaptureFilterRulesTcpOptionsDestinationPortRangeMax,
 *                 min: captureFilterVtapCaptureFilterRulesTcpOptionsDestinationPortRangeMin,
 *             },
 *             sourcePortRange: {
 *                 max: captureFilterVtapCaptureFilterRulesTcpOptionsSourcePortRangeMax,
 *                 min: captureFilterVtapCaptureFilterRulesTcpOptionsSourcePortRangeMin,
 *             },
 *         },
 *         udpOptions: {
 *             destinationPortRange: {
 *                 max: captureFilterVtapCaptureFilterRulesUdpOptionsDestinationPortRangeMax,
 *                 min: captureFilterVtapCaptureFilterRulesUdpOptionsDestinationPortRangeMin,
 *             },
 *             sourcePortRange: {
 *                 max: captureFilterVtapCaptureFilterRulesUdpOptionsSourcePortRangeMax,
 *                 min: captureFilterVtapCaptureFilterRulesUdpOptionsSourcePortRangeMin,
 *             },
 *         },
 *     }],
 * });
 * ```
 *
 * ## Import
 *
 * CaptureFilters can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Core/captureFilter:CaptureFilter test_capture_filter "id"
 * ```
 */
export class CaptureFilter extends pulumi.CustomResource {
    /**
     * Get an existing CaptureFilter resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: CaptureFilterState, opts?: pulumi.CustomResourceOptions): CaptureFilter {
        return new CaptureFilter(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Core/captureFilter:CaptureFilter';

    /**
     * Returns true if the given object is an instance of CaptureFilter.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is CaptureFilter {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === CaptureFilter.__pulumiType;
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the capture filter.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * Indicates which service will use this capture filter
     */
    public readonly filterType!: pulumi.Output<string>;
    /**
     * (Updatable) The set of rules governing what traffic the Flow Log collects when creating a flow log capture filter.
     */
    public readonly flowLogCaptureFilterRules!: pulumi.Output<outputs.Core.CaptureFilterFlowLogCaptureFilterRule[]>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The capture filter's current administrative state.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the capture filter was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2021-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * (Updatable) The set of rules governing what traffic a VTAP mirrors.
     */
    public readonly vtapCaptureFilterRules!: pulumi.Output<outputs.Core.CaptureFilterVtapCaptureFilterRule[]>;

    /**
     * Create a CaptureFilter resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: CaptureFilterArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: CaptureFilterArgs | CaptureFilterState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as CaptureFilterState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["filterType"] = state ? state.filterType : undefined;
            resourceInputs["flowLogCaptureFilterRules"] = state ? state.flowLogCaptureFilterRules : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["vtapCaptureFilterRules"] = state ? state.vtapCaptureFilterRules : undefined;
        } else {
            const args = argsOrState as CaptureFilterArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.filterType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'filterType'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["filterType"] = args ? args.filterType : undefined;
            resourceInputs["flowLogCaptureFilterRules"] = args ? args.flowLogCaptureFilterRules : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["vtapCaptureFilterRules"] = args ? args.vtapCaptureFilterRules : undefined;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(CaptureFilter.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering CaptureFilter resources.
 */
export interface CaptureFilterState {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the capture filter.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * Indicates which service will use this capture filter
     */
    filterType?: pulumi.Input<string>;
    /**
     * (Updatable) The set of rules governing what traffic the Flow Log collects when creating a flow log capture filter.
     */
    flowLogCaptureFilterRules?: pulumi.Input<pulumi.Input<inputs.Core.CaptureFilterFlowLogCaptureFilterRule>[]>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The capture filter's current administrative state.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the capture filter was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2021-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * (Updatable) The set of rules governing what traffic a VTAP mirrors.
     */
    vtapCaptureFilterRules?: pulumi.Input<pulumi.Input<inputs.Core.CaptureFilterVtapCaptureFilterRule>[]>;
}

/**
 * The set of arguments for constructing a CaptureFilter resource.
 */
export interface CaptureFilterArgs {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the capture filter.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * Indicates which service will use this capture filter
     */
    filterType: pulumi.Input<string>;
    /**
     * (Updatable) The set of rules governing what traffic the Flow Log collects when creating a flow log capture filter.
     */
    flowLogCaptureFilterRules?: pulumi.Input<pulumi.Input<inputs.Core.CaptureFilterFlowLogCaptureFilterRule>[]>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The set of rules governing what traffic a VTAP mirrors.
     */
    vtapCaptureFilterRules?: pulumi.Input<pulumi.Input<inputs.Core.CaptureFilterVtapCaptureFilterRule>[]>;
}
