// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Fleet Credential resource in Oracle Cloud Infrastructure Fleet Apps Management service.
 *
 * Add credentials to a fleet in Fleet Application Management.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFleetCredential = new oci.fleetappsmanagement.FleetCredential("test_fleet_credential", {
 *     displayName: fleetCredentialDisplayName,
 *     entitySpecifics: {
 *         credentialLevel: fleetCredentialEntitySpecificsCredentialLevel,
 *         resourceId: testResource.id,
 *         target: fleetCredentialEntitySpecificsTarget,
 *         variables: [{
 *             name: fleetCredentialEntitySpecificsVariablesName,
 *             value: fleetCredentialEntitySpecificsVariablesValue,
 *         }],
 *     },
 *     fleetId: testFleet.id,
 *     password: {
 *         credentialType: fleetCredentialPasswordCredentialType,
 *         keyId: testKey.id,
 *         keyVersion: fleetCredentialPasswordKeyVersion,
 *         secretId: testSecret.id,
 *         secretVersion: fleetCredentialPasswordSecretVersion,
 *         value: fleetCredentialPasswordValue,
 *         vaultId: testVault.id,
 *     },
 *     user: {
 *         credentialType: fleetCredentialUserCredentialType,
 *         keyId: testKey.id,
 *         keyVersion: fleetCredentialUserKeyVersion,
 *         secretId: testSecret.id,
 *         secretVersion: fleetCredentialUserSecretVersion,
 *         value: fleetCredentialUserValue,
 *         vaultId: testVault.id,
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * Import is not supported for this resource.
 */
export class FleetCredential extends pulumi.CustomResource {
    /**
     * Get an existing FleetCredential resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: FleetCredentialState, opts?: pulumi.CustomResourceOptions): FleetCredential {
        return new FleetCredential(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:FleetAppsManagement/fleetCredential:FleetCredential';

    /**
     * Returns true if the given object is an instance of FleetCredential.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is FleetCredential {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === FleetCredential.__pulumiType;
    }

    /**
     * Compartment OCID
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Credential specific Details.
     */
    public readonly entitySpecifics!: pulumi.Output<outputs.FleetAppsManagement.FleetCredentialEntitySpecifics>;
    /**
     * Unique Fleet identifier.
     */
    public readonly fleetId!: pulumi.Output<string>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * (Updatable) Credential Details.
     */
    public readonly password!: pulumi.Output<outputs.FleetAppsManagement.FleetCredentialPassword>;
    /**
     * The current state of the FleetCredential.
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
     * (Updatable) Credential Details.
     */
    public readonly user!: pulumi.Output<outputs.FleetAppsManagement.FleetCredentialUser>;

    /**
     * Create a FleetCredential resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: FleetCredentialArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: FleetCredentialArgs | FleetCredentialState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as FleetCredentialState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["entitySpecifics"] = state ? state.entitySpecifics : undefined;
            resourceInputs["fleetId"] = state ? state.fleetId : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["password"] = state ? state.password : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["user"] = state ? state.user : undefined;
        } else {
            const args = argsOrState as FleetCredentialArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.entitySpecifics === undefined) && !opts.urn) {
                throw new Error("Missing required property 'entitySpecifics'");
            }
            if ((!args || args.fleetId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'fleetId'");
            }
            if ((!args || args.password === undefined) && !opts.urn) {
                throw new Error("Missing required property 'password'");
            }
            if ((!args || args.user === undefined) && !opts.urn) {
                throw new Error("Missing required property 'user'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["entitySpecifics"] = args ? args.entitySpecifics : undefined;
            resourceInputs["fleetId"] = args ? args.fleetId : undefined;
            resourceInputs["password"] = args ? args.password : undefined;
            resourceInputs["user"] = args ? args.user : undefined;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(FleetCredential.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering FleetCredential resources.
 */
export interface FleetCredentialState {
    /**
     * Compartment OCID
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Credential specific Details.
     */
    entitySpecifics?: pulumi.Input<inputs.FleetAppsManagement.FleetCredentialEntitySpecifics>;
    /**
     * Unique Fleet identifier.
     */
    fleetId?: pulumi.Input<string>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * (Updatable) Credential Details.
     */
    password?: pulumi.Input<inputs.FleetAppsManagement.FleetCredentialPassword>;
    /**
     * The current state of the FleetCredential.
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
     * (Updatable) Credential Details.
     */
    user?: pulumi.Input<inputs.FleetAppsManagement.FleetCredentialUser>;
}

/**
 * The set of arguments for constructing a FleetCredential resource.
 */
export interface FleetCredentialArgs {
    /**
     * Compartment OCID
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Credential specific Details.
     */
    entitySpecifics: pulumi.Input<inputs.FleetAppsManagement.FleetCredentialEntitySpecifics>;
    /**
     * Unique Fleet identifier.
     */
    fleetId: pulumi.Input<string>;
    /**
     * (Updatable) Credential Details.
     */
    password: pulumi.Input<inputs.FleetAppsManagement.FleetCredentialPassword>;
    /**
     * (Updatable) Credential Details.
     */
    user: pulumi.Input<inputs.FleetAppsManagement.FleetCredentialUser>;
}
