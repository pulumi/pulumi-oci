// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Smtp Credential resource in Oracle Cloud Infrastructure Identity service.
 *
 * Creates a new SMTP credential for the specified user. An SMTP credential has an SMTP user name and an SMTP password.
 * You must specify a *description* for the SMTP credential (although it can be an empty string). It does not
 * have to be unique, and you can change it anytime with
 * [UpdateSmtpCredential](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/SmtpCredentialSummary/UpdateSmtpCredential).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSmtpCredential = new oci.identity.SmtpCredential("test_smtp_credential", {
 *     description: smtpCredentialDescription,
 *     userId: testUser.id,
 * });
 * ```
 *
 * ## Import
 *
 * SmtpCredentials can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Identity/smtpCredential:SmtpCredential test_smtp_credential "users/{userId}/smtpCredentials/{smtpCredentialId}"
 * ```
 */
export class SmtpCredential extends pulumi.CustomResource {
    /**
     * Get an existing SmtpCredential resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: SmtpCredentialState, opts?: pulumi.CustomResourceOptions): SmtpCredential {
        return new SmtpCredential(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Identity/smtpCredential:SmtpCredential';

    /**
     * Returns true if the given object is an instance of SmtpCredential.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is SmtpCredential {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === SmtpCredential.__pulumiType;
    }

    /**
     * (Updatable) The description you assign to the SMTP credentials during creation. Does not have to be unique, and it's changeable.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * The detailed status of INACTIVE lifecycleState.
     */
    public /*out*/ readonly inactiveState!: pulumi.Output<string>;
    /**
     * The SMTP password.
     */
    public /*out*/ readonly password!: pulumi.Output<string>;
    /**
     * The credential's current state.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Date and time the `SmtpCredential` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * Date and time when this credential will expire, in the format defined by RFC3339. Null if it never expires.  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeExpires!: pulumi.Output<string>;
    /**
     * The OCID of the user.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly userId!: pulumi.Output<string>;
    /**
     * The SMTP user name.
     */
    public /*out*/ readonly username!: pulumi.Output<string>;

    /**
     * Create a SmtpCredential resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: SmtpCredentialArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: SmtpCredentialArgs | SmtpCredentialState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as SmtpCredentialState | undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["inactiveState"] = state ? state.inactiveState : undefined;
            resourceInputs["password"] = state ? state.password : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeExpires"] = state ? state.timeExpires : undefined;
            resourceInputs["userId"] = state ? state.userId : undefined;
            resourceInputs["username"] = state ? state.username : undefined;
        } else {
            const args = argsOrState as SmtpCredentialArgs | undefined;
            if ((!args || args.description === undefined) && !opts.urn) {
                throw new Error("Missing required property 'description'");
            }
            if ((!args || args.userId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'userId'");
            }
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["userId"] = args ? args.userId : undefined;
            resourceInputs["inactiveState"] = undefined /*out*/;
            resourceInputs["password"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeExpires"] = undefined /*out*/;
            resourceInputs["username"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(SmtpCredential.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering SmtpCredential resources.
 */
export interface SmtpCredentialState {
    /**
     * (Updatable) The description you assign to the SMTP credentials during creation. Does not have to be unique, and it's changeable.
     */
    description?: pulumi.Input<string>;
    /**
     * The detailed status of INACTIVE lifecycleState.
     */
    inactiveState?: pulumi.Input<string>;
    /**
     * The SMTP password.
     */
    password?: pulumi.Input<string>;
    /**
     * The credential's current state.
     */
    state?: pulumi.Input<string>;
    /**
     * Date and time the `SmtpCredential` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * Date and time when this credential will expire, in the format defined by RFC3339. Null if it never expires.  Example: `2016-08-25T21:10:29.600Z`
     */
    timeExpires?: pulumi.Input<string>;
    /**
     * The OCID of the user.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    userId?: pulumi.Input<string>;
    /**
     * The SMTP user name.
     */
    username?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a SmtpCredential resource.
 */
export interface SmtpCredentialArgs {
    /**
     * (Updatable) The description you assign to the SMTP credentials during creation. Does not have to be unique, and it's changeable.
     */
    description: pulumi.Input<string>;
    /**
     * The OCID of the user.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    userId: pulumi.Input<string>;
}
