// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

export class SqlFirewallPolicyManagement extends pulumi.CustomResource {
    /**
     * Get an existing SqlFirewallPolicyManagement resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: SqlFirewallPolicyManagementState, opts?: pulumi.CustomResourceOptions): SqlFirewallPolicyManagement {
        return new SqlFirewallPolicyManagement(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DataSafe/sqlFirewallPolicyManagement:SqlFirewallPolicyManagement';

    /**
     * Returns true if the given object is an instance of SqlFirewallPolicyManagement.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is SqlFirewallPolicyManagement {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === SqlFirewallPolicyManagement.__pulumiType;
    }

    public readonly allowedClientIps!: pulumi.Output<string[]>;
    public readonly allowedClientOsUsernames!: pulumi.Output<string[]>;
    public readonly allowedClientPrograms!: pulumi.Output<string[]>;
    public readonly compartmentId!: pulumi.Output<string>;
    public readonly dbUserName!: pulumi.Output<string>;
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    public readonly description!: pulumi.Output<string>;
    public readonly displayName!: pulumi.Output<string>;
    public readonly enforcementScope!: pulumi.Output<string>;
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    public /*out*/ readonly securityPolicyId!: pulumi.Output<string>;
    public readonly sqlFirewallPolicyId!: pulumi.Output<string>;
    public /*out*/ readonly sqlLevel!: pulumi.Output<string>;
    public readonly state!: pulumi.Output<string>;
    public readonly status!: pulumi.Output<string>;
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: any}>;
    public readonly targetId!: pulumi.Output<string>;
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    public readonly violationAction!: pulumi.Output<string>;
    public readonly violationAudit!: pulumi.Output<string>;

    /**
     * Create a SqlFirewallPolicyManagement resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args?: SqlFirewallPolicyManagementArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: SqlFirewallPolicyManagementArgs | SqlFirewallPolicyManagementState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as SqlFirewallPolicyManagementState | undefined;
            resourceInputs["allowedClientIps"] = state ? state.allowedClientIps : undefined;
            resourceInputs["allowedClientOsUsernames"] = state ? state.allowedClientOsUsernames : undefined;
            resourceInputs["allowedClientPrograms"] = state ? state.allowedClientPrograms : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["dbUserName"] = state ? state.dbUserName : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["enforcementScope"] = state ? state.enforcementScope : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["securityPolicyId"] = state ? state.securityPolicyId : undefined;
            resourceInputs["sqlFirewallPolicyId"] = state ? state.sqlFirewallPolicyId : undefined;
            resourceInputs["sqlLevel"] = state ? state.sqlLevel : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["status"] = state ? state.status : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["targetId"] = state ? state.targetId : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["violationAction"] = state ? state.violationAction : undefined;
            resourceInputs["violationAudit"] = state ? state.violationAudit : undefined;
        } else {
            const args = argsOrState as SqlFirewallPolicyManagementArgs | undefined;
            resourceInputs["allowedClientIps"] = args ? args.allowedClientIps : undefined;
            resourceInputs["allowedClientOsUsernames"] = args ? args.allowedClientOsUsernames : undefined;
            resourceInputs["allowedClientPrograms"] = args ? args.allowedClientPrograms : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["dbUserName"] = args ? args.dbUserName : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["enforcementScope"] = args ? args.enforcementScope : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["sqlFirewallPolicyId"] = args ? args.sqlFirewallPolicyId : undefined;
            resourceInputs["state"] = args ? args.state : undefined;
            resourceInputs["status"] = args ? args.status : undefined;
            resourceInputs["targetId"] = args ? args.targetId : undefined;
            resourceInputs["violationAction"] = args ? args.violationAction : undefined;
            resourceInputs["violationAudit"] = args ? args.violationAudit : undefined;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["securityPolicyId"] = undefined /*out*/;
            resourceInputs["sqlLevel"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(SqlFirewallPolicyManagement.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering SqlFirewallPolicyManagement resources.
 */
export interface SqlFirewallPolicyManagementState {
    allowedClientIps?: pulumi.Input<pulumi.Input<string>[]>;
    allowedClientOsUsernames?: pulumi.Input<pulumi.Input<string>[]>;
    allowedClientPrograms?: pulumi.Input<pulumi.Input<string>[]>;
    compartmentId?: pulumi.Input<string>;
    dbUserName?: pulumi.Input<string>;
    definedTags?: pulumi.Input<{[key: string]: any}>;
    description?: pulumi.Input<string>;
    displayName?: pulumi.Input<string>;
    enforcementScope?: pulumi.Input<string>;
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    lifecycleDetails?: pulumi.Input<string>;
    securityPolicyId?: pulumi.Input<string>;
    sqlFirewallPolicyId?: pulumi.Input<string>;
    sqlLevel?: pulumi.Input<string>;
    state?: pulumi.Input<string>;
    status?: pulumi.Input<string>;
    systemTags?: pulumi.Input<{[key: string]: any}>;
    targetId?: pulumi.Input<string>;
    timeCreated?: pulumi.Input<string>;
    timeUpdated?: pulumi.Input<string>;
    violationAction?: pulumi.Input<string>;
    violationAudit?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a SqlFirewallPolicyManagement resource.
 */
export interface SqlFirewallPolicyManagementArgs {
    allowedClientIps?: pulumi.Input<pulumi.Input<string>[]>;
    allowedClientOsUsernames?: pulumi.Input<pulumi.Input<string>[]>;
    allowedClientPrograms?: pulumi.Input<pulumi.Input<string>[]>;
    compartmentId?: pulumi.Input<string>;
    dbUserName?: pulumi.Input<string>;
    definedTags?: pulumi.Input<{[key: string]: any}>;
    description?: pulumi.Input<string>;
    displayName?: pulumi.Input<string>;
    enforcementScope?: pulumi.Input<string>;
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    sqlFirewallPolicyId?: pulumi.Input<string>;
    state?: pulumi.Input<string>;
    status?: pulumi.Input<string>;
    targetId?: pulumi.Input<string>;
    violationAction?: pulumi.Input<string>;
    violationAudit?: pulumi.Input<string>;
}