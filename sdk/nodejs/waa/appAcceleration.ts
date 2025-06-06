// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Web App Acceleration resource in Oracle Cloud Infrastructure Waa service.
 *
 * Creates a new WebAppAcceleration.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testWebAppAcceleration = new oci.waa.AppAcceleration("test_web_app_acceleration", {
 *     backendType: webAppAccelerationBackendType,
 *     compartmentId: compartmentId,
 *     loadBalancerId: testLoadBalancer.id,
 *     webAppAccelerationPolicyId: testWebAppAccelerationPolicy.id,
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     displayName: webAppAccelerationDisplayName,
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 *     systemTags: webAppAccelerationSystemTags,
 * });
 * ```
 *
 * ## Import
 *
 * WebAppAccelerations can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Waa/appAcceleration:AppAcceleration test_web_app_acceleration "id"
 * ```
 */
export class AppAcceleration extends pulumi.CustomResource {
    /**
     * Get an existing AppAcceleration resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: AppAccelerationState, opts?: pulumi.CustomResourceOptions): AppAcceleration {
        return new AppAcceleration(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Waa/appAcceleration:AppAcceleration';

    /**
     * Returns true if the given object is an instance of AppAcceleration.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is AppAcceleration {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === AppAcceleration.__pulumiType;
    }

    /**
     * Type of the WebAppFirewall, as example LOAD_BALANCER.
     */
    public readonly backendType!: pulumi.Output<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) WebAppAcceleration display name, can be renamed.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in FAILED state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * LoadBalancer [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to which the WebAppAccelerationPolicy is attached to.
     */
    public readonly loadBalancerId!: pulumi.Output<string>;
    /**
     * The current state of the WebAppAcceleration.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * (Updatable) Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The time the WebAppAcceleration was created. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time the WebAppAcceleration was updated. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of WebAppAccelerationPolicy, which is attached to the resource.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly webAppAccelerationPolicyId!: pulumi.Output<string>;

    /**
     * Create a AppAcceleration resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: AppAccelerationArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: AppAccelerationArgs | AppAccelerationState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as AppAccelerationState | undefined;
            resourceInputs["backendType"] = state ? state.backendType : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["loadBalancerId"] = state ? state.loadBalancerId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["webAppAccelerationPolicyId"] = state ? state.webAppAccelerationPolicyId : undefined;
        } else {
            const args = argsOrState as AppAccelerationArgs | undefined;
            if ((!args || args.backendType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'backendType'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.loadBalancerId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'loadBalancerId'");
            }
            if ((!args || args.webAppAccelerationPolicyId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'webAppAccelerationPolicyId'");
            }
            resourceInputs["backendType"] = args ? args.backendType : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["loadBalancerId"] = args ? args.loadBalancerId : undefined;
            resourceInputs["systemTags"] = args ? args.systemTags : undefined;
            resourceInputs["webAppAccelerationPolicyId"] = args ? args.webAppAccelerationPolicyId : undefined;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(AppAcceleration.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering AppAcceleration resources.
 */
export interface AppAccelerationState {
    /**
     * Type of the WebAppFirewall, as example LOAD_BALANCER.
     */
    backendType?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) WebAppAcceleration display name, can be renamed.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in FAILED state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * LoadBalancer [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to which the WebAppAccelerationPolicy is attached to.
     */
    loadBalancerId?: pulumi.Input<string>;
    /**
     * The current state of the WebAppAcceleration.
     */
    state?: pulumi.Input<string>;
    /**
     * (Updatable) Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The time the WebAppAcceleration was created. An RFC3339 formatted datetime string.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time the WebAppAcceleration was updated. An RFC3339 formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of WebAppAccelerationPolicy, which is attached to the resource.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    webAppAccelerationPolicyId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a AppAcceleration resource.
 */
export interface AppAccelerationArgs {
    /**
     * Type of the WebAppFirewall, as example LOAD_BALANCER.
     */
    backendType: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) WebAppAcceleration display name, can be renamed.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * LoadBalancer [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to which the WebAppAccelerationPolicy is attached to.
     */
    loadBalancerId: pulumi.Input<string>;
    /**
     * (Updatable) Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of WebAppAccelerationPolicy, which is attached to the resource.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    webAppAccelerationPolicyId: pulumi.Input<string>;
}
