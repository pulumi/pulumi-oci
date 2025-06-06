// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Auth Token resource in Oracle Cloud Infrastructure Identity service.
 *
 * Creates a new auth token for the specified user. For information about what auth tokens are for, see
 * [Managing User Credentials](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingcredentials.htm).
 *
 * You must specify a *description* for the auth token (although it can be an empty string). It does not
 * have to be unique, and you can change it anytime with
 * [UpdateAuthToken](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/AuthToken/UpdateAuthToken).
 *
 * Every user has permission to create an auth token for *their own user ID*. An administrator in your organization
 * does not need to write a policy to give users this ability. To compare, administrators who have permission to the
 * tenancy can use this operation to create an auth token for any user, including themselves.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAuthToken = new oci.identity.AuthToken("test_auth_token", {
 *     description: authTokenDescription,
 *     userId: testUser.id,
 * });
 * ```
 *
 * ## Import
 *
 * AuthTokens can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Identity/authToken:AuthToken test_auth_token "users/{userId}/authTokens/{authTokenId}"
 * ```
 */
export class AuthToken extends pulumi.CustomResource {
    /**
     * Get an existing AuthToken resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: AuthTokenState, opts?: pulumi.CustomResourceOptions): AuthToken {
        return new AuthToken(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Identity/authToken:AuthToken';

    /**
     * Returns true if the given object is an instance of AuthToken.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is AuthToken {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === AuthToken.__pulumiType;
    }

    /**
     * (Updatable) The description you assign to the auth token during creation. Does not have to be unique, and it's changeable.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * The detailed status of INACTIVE lifecycleState.
     */
    public /*out*/ readonly inactiveState!: pulumi.Output<string>;
    /**
     * The token's current state.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Date and time the `AuthToken` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * Date and time when this auth token will expire, in the format defined by RFC3339. Null if it never expires.  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeExpires!: pulumi.Output<string>;
    /**
     * The auth token. The value is available only in the response for `CreateAuthToken`, and not for `ListAuthTokens` or `UpdateAuthToken`.
     */
    public /*out*/ readonly token!: pulumi.Output<string>;
    /**
     * The OCID of the user.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly userId!: pulumi.Output<string>;

    /**
     * Create a AuthToken resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: AuthTokenArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: AuthTokenArgs | AuthTokenState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as AuthTokenState | undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["inactiveState"] = state ? state.inactiveState : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeExpires"] = state ? state.timeExpires : undefined;
            resourceInputs["token"] = state ? state.token : undefined;
            resourceInputs["userId"] = state ? state.userId : undefined;
        } else {
            const args = argsOrState as AuthTokenArgs | undefined;
            if ((!args || args.description === undefined) && !opts.urn) {
                throw new Error("Missing required property 'description'");
            }
            if ((!args || args.userId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'userId'");
            }
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["userId"] = args ? args.userId : undefined;
            resourceInputs["inactiveState"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeExpires"] = undefined /*out*/;
            resourceInputs["token"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(AuthToken.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering AuthToken resources.
 */
export interface AuthTokenState {
    /**
     * (Updatable) The description you assign to the auth token during creation. Does not have to be unique, and it's changeable.
     */
    description?: pulumi.Input<string>;
    /**
     * The detailed status of INACTIVE lifecycleState.
     */
    inactiveState?: pulumi.Input<string>;
    /**
     * The token's current state.
     */
    state?: pulumi.Input<string>;
    /**
     * Date and time the `AuthToken` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * Date and time when this auth token will expire, in the format defined by RFC3339. Null if it never expires.  Example: `2016-08-25T21:10:29.600Z`
     */
    timeExpires?: pulumi.Input<string>;
    /**
     * The auth token. The value is available only in the response for `CreateAuthToken`, and not for `ListAuthTokens` or `UpdateAuthToken`.
     */
    token?: pulumi.Input<string>;
    /**
     * The OCID of the user.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    userId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a AuthToken resource.
 */
export interface AuthTokenArgs {
    /**
     * (Updatable) The description you assign to the auth token during creation. Does not have to be unique, and it's changeable.
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
