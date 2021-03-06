// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Swift Password resource in Oracle Cloud Infrastructure Identity service.
 *
 * **Deprecated. Use [CreateAuthToken](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/AuthToken/CreateAuthToken) instead.**
 *
 * Creates a new Swift password for the specified user. For information about what Swift passwords are for, see
 * [Managing User Credentials](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingcredentials.htm).
 *
 * You must specify a *description* for the Swift password (although it can be an empty string). It does not
 * have to be unique, and you can change it anytime with
 * [UpdateSwiftPassword](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/SwiftPassword/UpdateSwiftPassword).
 *
 * Every user has permission to create a Swift password for *their own user ID*. An administrator in your organization
 * does not need to write a policy to give users this ability. To compare, administrators who have permission to the
 * tenancy can use this operation to create a Swift password for any user, including themselves.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSwiftPassword = new oci.identity.SwiftPassword("testSwiftPassword", {
 *     description: _var.swift_password_description,
 *     userId: oci_identity_user.test_user.id,
 * });
 * ```
 *
 * ## Import
 *
 * SwiftPasswords can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:Identity/swiftPassword:SwiftPassword test_swift_password "users/{userId}/swiftPasswords/{swiftPasswordId}"
 * ```
 */
export class SwiftPassword extends pulumi.CustomResource {
    /**
     * Get an existing SwiftPassword resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: SwiftPasswordState, opts?: pulumi.CustomResourceOptions): SwiftPassword {
        return new SwiftPassword(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Identity/swiftPassword:SwiftPassword';

    /**
     * Returns true if the given object is an instance of SwiftPassword.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is SwiftPassword {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === SwiftPassword.__pulumiType;
    }

    /**
     * (Updatable) The description you assign to the Swift password during creation. Does not have to be unique, and it's changeable.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * Date and time when this password will expire, in the format defined by RFC3339. Null if it never expires.  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly expiresOn!: pulumi.Output<string>;
    /**
     * The detailed status of INACTIVE lifecycleState.
     */
    public /*out*/ readonly inactiveState!: pulumi.Output<string>;
    /**
     * The Swift password. The value is available only in the response for `CreateSwiftPassword`, and not for `ListSwiftPasswords` or `UpdateSwiftPassword`.
     */
    public /*out*/ readonly password!: pulumi.Output<string>;
    /**
     * The password's current state.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Date and time the `SwiftPassword` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The OCID of the user.
     */
    public readonly userId!: pulumi.Output<string>;

    /**
     * Create a SwiftPassword resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: SwiftPasswordArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: SwiftPasswordArgs | SwiftPasswordState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as SwiftPasswordState | undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["expiresOn"] = state ? state.expiresOn : undefined;
            resourceInputs["inactiveState"] = state ? state.inactiveState : undefined;
            resourceInputs["password"] = state ? state.password : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["userId"] = state ? state.userId : undefined;
        } else {
            const args = argsOrState as SwiftPasswordArgs | undefined;
            if ((!args || args.description === undefined) && !opts.urn) {
                throw new Error("Missing required property 'description'");
            }
            if ((!args || args.userId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'userId'");
            }
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["userId"] = args ? args.userId : undefined;
            resourceInputs["expiresOn"] = undefined /*out*/;
            resourceInputs["inactiveState"] = undefined /*out*/;
            resourceInputs["password"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(SwiftPassword.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering SwiftPassword resources.
 */
export interface SwiftPasswordState {
    /**
     * (Updatable) The description you assign to the Swift password during creation. Does not have to be unique, and it's changeable.
     */
    description?: pulumi.Input<string>;
    /**
     * Date and time when this password will expire, in the format defined by RFC3339. Null if it never expires.  Example: `2016-08-25T21:10:29.600Z`
     */
    expiresOn?: pulumi.Input<string>;
    /**
     * The detailed status of INACTIVE lifecycleState.
     */
    inactiveState?: pulumi.Input<string>;
    /**
     * The Swift password. The value is available only in the response for `CreateSwiftPassword`, and not for `ListSwiftPasswords` or `UpdateSwiftPassword`.
     */
    password?: pulumi.Input<string>;
    /**
     * The password's current state.
     */
    state?: pulumi.Input<string>;
    /**
     * Date and time the `SwiftPassword` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The OCID of the user.
     */
    userId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a SwiftPassword resource.
 */
export interface SwiftPasswordArgs {
    /**
     * (Updatable) The description you assign to the Swift password during creation. Does not have to be unique, and it's changeable.
     */
    description: pulumi.Input<string>;
    /**
     * The OCID of the user.
     */
    userId: pulumi.Input<string>;
}
