// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Onboarding resource in Oracle Cloud Infrastructure Fleet Apps Management service.
 *
 * Onboard a tenant to Fleet Application Management Service
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOnboarding = new oci.fleetappsmanagement.Onboarding("test_onboarding", {
 *     compartmentId: compartmentId,
 *     isCostTrackingTagEnabled: onboardingIsCostTrackingTagEnabled,
 *     isFamsTagEnabled: onboardingIsFamsTagEnabled,
 * });
 * ```
 *
 * ## Import
 *
 * Import is not supported for this resource.
 */
export class Onboarding extends pulumi.CustomResource {
    /**
     * Get an existing Onboarding resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: OnboardingState, opts?: pulumi.CustomResourceOptions): Onboarding {
        return new Onboarding(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:FleetAppsManagement/onboarding:Onboarding';

    /**
     * Returns true if the given object is an instance of Onboarding.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Onboarding {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Onboarding.__pulumiType;
    }

    /**
     * Tenancy OCID
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * A value determining if cost tracking tag is enabled or not
     */
    public readonly isCostTrackingTagEnabled!: pulumi.Output<boolean>;
    /**
     * A value determining FAMS tag is enabled or not
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly isFamsTagEnabled!: pulumi.Output<boolean>;
    /**
     * Associated region
     */
    public /*out*/ readonly resourceRegion!: pulumi.Output<string>;
    /**
     * The current state of the Onboarding.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The time this resource was created. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time this resource was last updated. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * Version of FAMS the tenant is onboarded to.
     */
    public /*out*/ readonly version!: pulumi.Output<string>;

    /**
     * Create a Onboarding resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: OnboardingArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: OnboardingArgs | OnboardingState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as OnboardingState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["isCostTrackingTagEnabled"] = state ? state.isCostTrackingTagEnabled : undefined;
            resourceInputs["isFamsTagEnabled"] = state ? state.isFamsTagEnabled : undefined;
            resourceInputs["resourceRegion"] = state ? state.resourceRegion : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["version"] = state ? state.version : undefined;
        } else {
            const args = argsOrState as OnboardingArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["isCostTrackingTagEnabled"] = args ? args.isCostTrackingTagEnabled : undefined;
            resourceInputs["isFamsTagEnabled"] = args ? args.isFamsTagEnabled : undefined;
            resourceInputs["resourceRegion"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
            resourceInputs["version"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(Onboarding.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Onboarding resources.
 */
export interface OnboardingState {
    /**
     * Tenancy OCID
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * A value determining if cost tracking tag is enabled or not
     */
    isCostTrackingTagEnabled?: pulumi.Input<boolean>;
    /**
     * A value determining FAMS tag is enabled or not
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    isFamsTagEnabled?: pulumi.Input<boolean>;
    /**
     * Associated region
     */
    resourceRegion?: pulumi.Input<string>;
    /**
     * The current state of the Onboarding.
     */
    state?: pulumi.Input<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The time this resource was created. An RFC3339 formatted datetime string.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time this resource was last updated. An RFC3339 formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * Version of FAMS the tenant is onboarded to.
     */
    version?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Onboarding resource.
 */
export interface OnboardingArgs {
    /**
     * Tenancy OCID
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A value determining if cost tracking tag is enabled or not
     */
    isCostTrackingTagEnabled?: pulumi.Input<boolean>;
    /**
     * A value determining FAMS tag is enabled or not
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    isFamsTagEnabled?: pulumi.Input<boolean>;
}
