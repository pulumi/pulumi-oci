// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

export class AutonomousContainerDatabaseDataguardRoleChange extends pulumi.CustomResource {
    /**
     * Get an existing AutonomousContainerDatabaseDataguardRoleChange resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: AutonomousContainerDatabaseDataguardRoleChangeState, opts?: pulumi.CustomResourceOptions): AutonomousContainerDatabaseDataguardRoleChange {
        return new AutonomousContainerDatabaseDataguardRoleChange(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Database/autonomousContainerDatabaseDataguardRoleChange:AutonomousContainerDatabaseDataguardRoleChange';

    /**
     * Returns true if the given object is an instance of AutonomousContainerDatabaseDataguardRoleChange.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is AutonomousContainerDatabaseDataguardRoleChange {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === AutonomousContainerDatabaseDataguardRoleChange.__pulumiType;
    }

    public readonly autonomousContainerDatabaseDataguardAssociationId!: pulumi.Output<string>;
    public readonly autonomousContainerDatabaseId!: pulumi.Output<string>;
    public readonly connectionStringsType!: pulumi.Output<string | undefined>;
    public readonly role!: pulumi.Output<string>;

    /**
     * Create a AutonomousContainerDatabaseDataguardRoleChange resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: AutonomousContainerDatabaseDataguardRoleChangeArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: AutonomousContainerDatabaseDataguardRoleChangeArgs | AutonomousContainerDatabaseDataguardRoleChangeState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as AutonomousContainerDatabaseDataguardRoleChangeState | undefined;
            resourceInputs["autonomousContainerDatabaseDataguardAssociationId"] = state ? state.autonomousContainerDatabaseDataguardAssociationId : undefined;
            resourceInputs["autonomousContainerDatabaseId"] = state ? state.autonomousContainerDatabaseId : undefined;
            resourceInputs["connectionStringsType"] = state ? state.connectionStringsType : undefined;
            resourceInputs["role"] = state ? state.role : undefined;
        } else {
            const args = argsOrState as AutonomousContainerDatabaseDataguardRoleChangeArgs | undefined;
            if ((!args || args.autonomousContainerDatabaseDataguardAssociationId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'autonomousContainerDatabaseDataguardAssociationId'");
            }
            if ((!args || args.autonomousContainerDatabaseId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'autonomousContainerDatabaseId'");
            }
            if ((!args || args.role === undefined) && !opts.urn) {
                throw new Error("Missing required property 'role'");
            }
            resourceInputs["autonomousContainerDatabaseDataguardAssociationId"] = args ? args.autonomousContainerDatabaseDataguardAssociationId : undefined;
            resourceInputs["autonomousContainerDatabaseId"] = args ? args.autonomousContainerDatabaseId : undefined;
            resourceInputs["connectionStringsType"] = args ? args.connectionStringsType : undefined;
            resourceInputs["role"] = args ? args.role : undefined;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(AutonomousContainerDatabaseDataguardRoleChange.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering AutonomousContainerDatabaseDataguardRoleChange resources.
 */
export interface AutonomousContainerDatabaseDataguardRoleChangeState {
    autonomousContainerDatabaseDataguardAssociationId?: pulumi.Input<string>;
    autonomousContainerDatabaseId?: pulumi.Input<string>;
    connectionStringsType?: pulumi.Input<string>;
    role?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a AutonomousContainerDatabaseDataguardRoleChange resource.
 */
export interface AutonomousContainerDatabaseDataguardRoleChangeArgs {
    autonomousContainerDatabaseDataguardAssociationId: pulumi.Input<string>;
    autonomousContainerDatabaseId: pulumi.Input<string>;
    connectionStringsType?: pulumi.Input<string>;
    role: pulumi.Input<string>;
}
