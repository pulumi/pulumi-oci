// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Autonomous Database Regional Wallet Management resource in Oracle Cloud Infrastructure Database service.
 *
 * Updates the Autonomous Database regional wallet.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutonomousDatabaseRegionalWalletManagement = new oci.database.AutonomousDatabaseRegionalWalletManagement("test_autonomous_database_regional_wallet_management", {
 *     gracePeriod: autonomousDatabaseRegionalWalletManagementGracePeriod,
 *     shouldRotate: autonomousDatabaseRegionalWalletManagementShouldRotate,
 * });
 * ```
 *
 * ## Import
 *
 * Import is not supported for this resource.
 */
export class AutonomousDatabaseRegionalWalletManagement extends pulumi.CustomResource {
    /**
     * Get an existing AutonomousDatabaseRegionalWalletManagement resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: AutonomousDatabaseRegionalWalletManagementState, opts?: pulumi.CustomResourceOptions): AutonomousDatabaseRegionalWalletManagement {
        return new AutonomousDatabaseRegionalWalletManagement(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Database/autonomousDatabaseRegionalWalletManagement:AutonomousDatabaseRegionalWalletManagement';

    /**
     * Returns true if the given object is an instance of AutonomousDatabaseRegionalWalletManagement.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is AutonomousDatabaseRegionalWalletManagement {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === AutonomousDatabaseRegionalWalletManagement.__pulumiType;
    }

    /**
     * (Updatable) The number of hours that the old wallet can be used after it has been rotated. The old wallet will no longer be valid after the number of hours in the wallet rotation grace period has passed. During the grace period, both the old wallet and the current wallet can be used.
     */
    public readonly gracePeriod!: pulumi.Output<number>;
    /**
     * (Updatable) Indicates whether to rotate the wallet or not. If `false`, the wallet will not be rotated. The default is `false`.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly shouldRotate!: pulumi.Output<boolean | undefined>;
    /**
     * The current lifecycle state of the Autonomous Database wallet.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the wallet was last rotated.
     */
    public /*out*/ readonly timeRotated!: pulumi.Output<string>;

    /**
     * Create a AutonomousDatabaseRegionalWalletManagement resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args?: AutonomousDatabaseRegionalWalletManagementArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: AutonomousDatabaseRegionalWalletManagementArgs | AutonomousDatabaseRegionalWalletManagementState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as AutonomousDatabaseRegionalWalletManagementState | undefined;
            resourceInputs["gracePeriod"] = state ? state.gracePeriod : undefined;
            resourceInputs["shouldRotate"] = state ? state.shouldRotate : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeRotated"] = state ? state.timeRotated : undefined;
        } else {
            const args = argsOrState as AutonomousDatabaseRegionalWalletManagementArgs | undefined;
            resourceInputs["gracePeriod"] = args ? args.gracePeriod : undefined;
            resourceInputs["shouldRotate"] = args ? args.shouldRotate : undefined;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeRotated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(AutonomousDatabaseRegionalWalletManagement.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering AutonomousDatabaseRegionalWalletManagement resources.
 */
export interface AutonomousDatabaseRegionalWalletManagementState {
    /**
     * (Updatable) The number of hours that the old wallet can be used after it has been rotated. The old wallet will no longer be valid after the number of hours in the wallet rotation grace period has passed. During the grace period, both the old wallet and the current wallet can be used.
     */
    gracePeriod?: pulumi.Input<number>;
    /**
     * (Updatable) Indicates whether to rotate the wallet or not. If `false`, the wallet will not be rotated. The default is `false`.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    shouldRotate?: pulumi.Input<boolean>;
    /**
     * The current lifecycle state of the Autonomous Database wallet.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the wallet was last rotated.
     */
    timeRotated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a AutonomousDatabaseRegionalWalletManagement resource.
 */
export interface AutonomousDatabaseRegionalWalletManagementArgs {
    /**
     * (Updatable) The number of hours that the old wallet can be used after it has been rotated. The old wallet will no longer be valid after the number of hours in the wallet rotation grace period has passed. During the grace period, both the old wallet and the current wallet can be used.
     */
    gracePeriod?: pulumi.Input<number>;
    /**
     * (Updatable) Indicates whether to rotate the wallet or not. If `false`, the wallet will not be rotated. The default is `false`.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    shouldRotate?: pulumi.Input<boolean>;
}
