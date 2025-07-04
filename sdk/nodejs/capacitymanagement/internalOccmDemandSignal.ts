// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Internal Occm Demand Signal resource in Oracle Cloud Infrastructure Capacity Management service.
 *
 * This is a internal PUT API which shall be used to update the metadata of the demand signal.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testInternalOccmDemandSignal = new oci.capacitymanagement.InternalOccmDemandSignal("test_internal_occm_demand_signal", {
 *     occmDemandSignalId: testOccmDemandSignal.id,
 *     lifecycleDetails: internalOccmDemandSignalLifecycleDetails,
 * });
 * ```
 *
 * ## Import
 *
 * InternalOccmDemandSignals can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:CapacityManagement/internalOccmDemandSignal:InternalOccmDemandSignal test_internal_occm_demand_signal "internal/occmDemandSignals/{occmDemandSignalId}"
 * ```
 */
export class InternalOccmDemandSignal extends pulumi.CustomResource {
    /**
     * Get an existing InternalOccmDemandSignal resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: InternalOccmDemandSignalState, opts?: pulumi.CustomResourceOptions): InternalOccmDemandSignal {
        return new InternalOccmDemandSignal(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:CapacityManagement/internalOccmDemandSignal:InternalOccmDemandSignal';

    /**
     * Returns true if the given object is an instance of InternalOccmDemandSignal.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is InternalOccmDemandSignal {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === InternalOccmDemandSignal.__pulumiType;
    }

    /**
     * The OCID of the tenancy from which the request to create the demand signal was made.
     */
    public /*out*/ readonly compartmentId!: pulumi.Output<string>;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public /*out*/ readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * A short description about the demand signal.
     */
    public /*out*/ readonly description!: pulumi.Output<string>;
    /**
     * The display name of the demand signal.
     */
    public /*out*/ readonly displayName!: pulumi.Output<string>;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public /*out*/ readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) The subset of demand signal states available for operators for updating the demand signal.
     *
     * IN_PROGRESS > Transitions the demand signal to IN_PROGRESS state. REJECTED > Transitions the demand signal to REJECTED state. COMPLETED > This will transition the demand signal to COMPLETED state.
     */
    public readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * The OCID of the customer group in which the demand signal is created.
     */
    public /*out*/ readonly occCustomerGroupId!: pulumi.Output<string>;
    /**
     * The OCID of the demand signal. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly occmDemandSignalId!: pulumi.Output<string>;
    /**
     * The current lifecycle state of the demand signal.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The time when the demand signal was created.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time when the demand signal was last updated.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a InternalOccmDemandSignal resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: InternalOccmDemandSignalArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: InternalOccmDemandSignalArgs | InternalOccmDemandSignalState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as InternalOccmDemandSignalState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["occCustomerGroupId"] = state ? state.occCustomerGroupId : undefined;
            resourceInputs["occmDemandSignalId"] = state ? state.occmDemandSignalId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as InternalOccmDemandSignalArgs | undefined;
            if ((!args || args.occmDemandSignalId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'occmDemandSignalId'");
            }
            resourceInputs["lifecycleDetails"] = args ? args.lifecycleDetails : undefined;
            resourceInputs["occmDemandSignalId"] = args ? args.occmDemandSignalId : undefined;
            resourceInputs["compartmentId"] = undefined /*out*/;
            resourceInputs["definedTags"] = undefined /*out*/;
            resourceInputs["description"] = undefined /*out*/;
            resourceInputs["displayName"] = undefined /*out*/;
            resourceInputs["freeformTags"] = undefined /*out*/;
            resourceInputs["occCustomerGroupId"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(InternalOccmDemandSignal.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering InternalOccmDemandSignal resources.
 */
export interface InternalOccmDemandSignalState {
    /**
     * The OCID of the tenancy from which the request to create the demand signal was made.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * A short description about the demand signal.
     */
    description?: pulumi.Input<string>;
    /**
     * The display name of the demand signal.
     */
    displayName?: pulumi.Input<string>;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The subset of demand signal states available for operators for updating the demand signal.
     *
     * IN_PROGRESS > Transitions the demand signal to IN_PROGRESS state. REJECTED > Transitions the demand signal to REJECTED state. COMPLETED > This will transition the demand signal to COMPLETED state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The OCID of the customer group in which the demand signal is created.
     */
    occCustomerGroupId?: pulumi.Input<string>;
    /**
     * The OCID of the demand signal. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    occmDemandSignalId?: pulumi.Input<string>;
    /**
     * The current lifecycle state of the demand signal.
     */
    state?: pulumi.Input<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The time when the demand signal was created.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time when the demand signal was last updated.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a InternalOccmDemandSignal resource.
 */
export interface InternalOccmDemandSignalArgs {
    /**
     * (Updatable) The subset of demand signal states available for operators for updating the demand signal.
     *
     * IN_PROGRESS > Transitions the demand signal to IN_PROGRESS state. REJECTED > Transitions the demand signal to REJECTED state. COMPLETED > This will transition the demand signal to COMPLETED state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The OCID of the demand signal. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    occmDemandSignalId: pulumi.Input<string>;
}
