// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Fusion Environment Admin User resource in Oracle Cloud Infrastructure Fusion Apps service.
 *
 * Create a FusionEnvironment admin user
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testFusionEnvironmentAdminUser = new oci.fusionapps.FusionEnvironmentAdminUser("testFusionEnvironmentAdminUser", {
 *     emailAddress: _var.fusion_environment_admin_user_email_address,
 *     firstName: _var.fusion_environment_admin_user_first_name,
 *     fusionEnvironmentId: oci_fusion_apps_fusion_environment.test_fusion_environment.id,
 *     lastName: _var.fusion_environment_admin_user_last_name,
 *     password: _var.fusion_environment_admin_user_password,
 *     username: _var.fusion_environment_admin_user_username,
 * });
 * ```
 *
 * ## Import
 *
 * FusionEnvironmentAdminUsers can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:FusionApps/fusionEnvironmentAdminUser:FusionEnvironmentAdminUser test_fusion_environment_admin_user "fusionEnvironments/{fusionEnvironmentId}/adminUsers/{adminUsername}"
 * ```
 */
export class FusionEnvironmentAdminUser extends pulumi.CustomResource {
    /**
     * Get an existing FusionEnvironmentAdminUser resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: FusionEnvironmentAdminUserState, opts?: pulumi.CustomResourceOptions): FusionEnvironmentAdminUser {
        return new FusionEnvironmentAdminUser(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:FusionApps/fusionEnvironmentAdminUser:FusionEnvironmentAdminUser';

    /**
     * Returns true if the given object is an instance of FusionEnvironmentAdminUser.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is FusionEnvironmentAdminUser {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === FusionEnvironmentAdminUser.__pulumiType;
    }

    /**
     * The email address for the administrator.
     */
    public readonly emailAddress!: pulumi.Output<string>;
    /**
     * The administrator's first name.
     */
    public readonly firstName!: pulumi.Output<string>;
    /**
     * unique FusionEnvironment identifier
     */
    public readonly fusionEnvironmentId!: pulumi.Output<string>;
    /**
     * A page of AdminUserSummary objects.
     */
    public /*out*/ readonly items!: pulumi.Output<outputs.FusionApps.FusionEnvironmentAdminUserItem[]>;
    /**
     * The administrator's last name.
     */
    public readonly lastName!: pulumi.Output<string>;
    /**
     * The password for the administrator.
     */
    public readonly password!: pulumi.Output<string>;
    /**
     * The username for the administrator.
     */
    public readonly username!: pulumi.Output<string>;

    /**
     * Create a FusionEnvironmentAdminUser resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: FusionEnvironmentAdminUserArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: FusionEnvironmentAdminUserArgs | FusionEnvironmentAdminUserState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as FusionEnvironmentAdminUserState | undefined;
            resourceInputs["emailAddress"] = state ? state.emailAddress : undefined;
            resourceInputs["firstName"] = state ? state.firstName : undefined;
            resourceInputs["fusionEnvironmentId"] = state ? state.fusionEnvironmentId : undefined;
            resourceInputs["items"] = state ? state.items : undefined;
            resourceInputs["lastName"] = state ? state.lastName : undefined;
            resourceInputs["password"] = state ? state.password : undefined;
            resourceInputs["username"] = state ? state.username : undefined;
        } else {
            const args = argsOrState as FusionEnvironmentAdminUserArgs | undefined;
            if ((!args || args.emailAddress === undefined) && !opts.urn) {
                throw new Error("Missing required property 'emailAddress'");
            }
            if ((!args || args.firstName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'firstName'");
            }
            if ((!args || args.fusionEnvironmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'fusionEnvironmentId'");
            }
            if ((!args || args.lastName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'lastName'");
            }
            if ((!args || args.password === undefined) && !opts.urn) {
                throw new Error("Missing required property 'password'");
            }
            if ((!args || args.username === undefined) && !opts.urn) {
                throw new Error("Missing required property 'username'");
            }
            resourceInputs["emailAddress"] = args ? args.emailAddress : undefined;
            resourceInputs["firstName"] = args ? args.firstName : undefined;
            resourceInputs["fusionEnvironmentId"] = args ? args.fusionEnvironmentId : undefined;
            resourceInputs["lastName"] = args ? args.lastName : undefined;
            resourceInputs["password"] = args ? args.password : undefined;
            resourceInputs["username"] = args ? args.username : undefined;
            resourceInputs["items"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(FusionEnvironmentAdminUser.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering FusionEnvironmentAdminUser resources.
 */
export interface FusionEnvironmentAdminUserState {
    /**
     * The email address for the administrator.
     */
    emailAddress?: pulumi.Input<string>;
    /**
     * The administrator's first name.
     */
    firstName?: pulumi.Input<string>;
    /**
     * unique FusionEnvironment identifier
     */
    fusionEnvironmentId?: pulumi.Input<string>;
    /**
     * A page of AdminUserSummary objects.
     */
    items?: pulumi.Input<pulumi.Input<inputs.FusionApps.FusionEnvironmentAdminUserItem>[]>;
    /**
     * The administrator's last name.
     */
    lastName?: pulumi.Input<string>;
    /**
     * The password for the administrator.
     */
    password?: pulumi.Input<string>;
    /**
     * The username for the administrator.
     */
    username?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a FusionEnvironmentAdminUser resource.
 */
export interface FusionEnvironmentAdminUserArgs {
    /**
     * The email address for the administrator.
     */
    emailAddress: pulumi.Input<string>;
    /**
     * The administrator's first name.
     */
    firstName: pulumi.Input<string>;
    /**
     * unique FusionEnvironment identifier
     */
    fusionEnvironmentId: pulumi.Input<string>;
    /**
     * The administrator's last name.
     */
    lastName: pulumi.Input<string>;
    /**
     * The password for the administrator.
     */
    password: pulumi.Input<string>;
    /**
     * The username for the administrator.
     */
    username: pulumi.Input<string>;
}