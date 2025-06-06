// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Wlp Agent resource in Oracle Cloud Infrastructure Cloud Guard service.
 *
 * Creates and registers a WLP agent for an
 * on-premise resource.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testWlpAgent = new oci.cloudguard.WlpAgent("test_wlp_agent", {
 *     agentVersion: wlpAgentAgentVersion,
 *     certificateSignedRequest: wlpAgentCertificateSignedRequest,
 *     compartmentId: compartmentId,
 *     osInfo: wlpAgentOsInfo,
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
 * WlpAgents can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:CloudGuard/wlpAgent:WlpAgent test_wlp_agent "id"
 * ```
 */
export class WlpAgent extends pulumi.CustomResource {
    /**
     * Get an existing WlpAgent resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: WlpAgentState, opts?: pulumi.CustomResourceOptions): WlpAgent {
        return new WlpAgent(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:CloudGuard/wlpAgent:WlpAgent';

    /**
     * Returns true if the given object is an instance of WlpAgent.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is WlpAgent {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === WlpAgent.__pulumiType;
    }

    /**
     * The version of the agent making the request
     */
    public readonly agentVersion!: pulumi.Output<string>;
    /**
     * The certificate ID returned by Oracle Cloud Infrastructure certificates service
     */
    public /*out*/ readonly certificateId!: pulumi.Output<string>;
    /**
     * (Updatable) The certificate signed request containing domain, organization names, organization units, city, state, country, email and public key, among other certificate details, signed by private key
     */
    public readonly certificateSignedRequest!: pulumi.Output<string>;
    /**
     * Compartment OCID of the host
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     *
     * Avoid entering confidential information.
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * OCID for instance in which WlpAgent is installed
     */
    public /*out*/ readonly hostId!: pulumi.Output<string>;
    /**
     * Concatenated OS name, OS version and agent architecture; for example, ubuntu_22.0_amd64.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly osInfo!: pulumi.Output<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * TenantId of the host
     */
    public /*out*/ readonly tenantId!: pulumi.Output<string>;
    /**
     * The date and time the WlpAgent was created. Format defined by RFC3339.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the WlpAgent was updated. Format defined by RFC3339.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a WlpAgent resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: WlpAgentArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: WlpAgentArgs | WlpAgentState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as WlpAgentState | undefined;
            resourceInputs["agentVersion"] = state ? state.agentVersion : undefined;
            resourceInputs["certificateId"] = state ? state.certificateId : undefined;
            resourceInputs["certificateSignedRequest"] = state ? state.certificateSignedRequest : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["hostId"] = state ? state.hostId : undefined;
            resourceInputs["osInfo"] = state ? state.osInfo : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["tenantId"] = state ? state.tenantId : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as WlpAgentArgs | undefined;
            if ((!args || args.agentVersion === undefined) && !opts.urn) {
                throw new Error("Missing required property 'agentVersion'");
            }
            if ((!args || args.certificateSignedRequest === undefined) && !opts.urn) {
                throw new Error("Missing required property 'certificateSignedRequest'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.osInfo === undefined) && !opts.urn) {
                throw new Error("Missing required property 'osInfo'");
            }
            resourceInputs["agentVersion"] = args ? args.agentVersion : undefined;
            resourceInputs["certificateSignedRequest"] = args ? args.certificateSignedRequest : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["osInfo"] = args ? args.osInfo : undefined;
            resourceInputs["certificateId"] = undefined /*out*/;
            resourceInputs["hostId"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["tenantId"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(WlpAgent.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering WlpAgent resources.
 */
export interface WlpAgentState {
    /**
     * The version of the agent making the request
     */
    agentVersion?: pulumi.Input<string>;
    /**
     * The certificate ID returned by Oracle Cloud Infrastructure certificates service
     */
    certificateId?: pulumi.Input<string>;
    /**
     * (Updatable) The certificate signed request containing domain, organization names, organization units, city, state, country, email and public key, among other certificate details, signed by private key
     */
    certificateSignedRequest?: pulumi.Input<string>;
    /**
     * Compartment OCID of the host
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     *
     * Avoid entering confidential information.
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * OCID for instance in which WlpAgent is installed
     */
    hostId?: pulumi.Input<string>;
    /**
     * Concatenated OS name, OS version and agent architecture; for example, ubuntu_22.0_amd64.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    osInfo?: pulumi.Input<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * TenantId of the host
     */
    tenantId?: pulumi.Input<string>;
    /**
     * The date and time the WlpAgent was created. Format defined by RFC3339.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the WlpAgent was updated. Format defined by RFC3339.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a WlpAgent resource.
 */
export interface WlpAgentArgs {
    /**
     * The version of the agent making the request
     */
    agentVersion: pulumi.Input<string>;
    /**
     * (Updatable) The certificate signed request containing domain, organization names, organization units, city, state, country, email and public key, among other certificate details, signed by private key
     */
    certificateSignedRequest: pulumi.Input<string>;
    /**
     * Compartment OCID of the host
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     *
     * Avoid entering confidential information.
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Concatenated OS name, OS version and agent architecture; for example, ubuntu_22.0_amd64.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    osInfo: pulumi.Input<string>;
}
