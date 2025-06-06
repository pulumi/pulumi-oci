// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Idp Group Mapping resource in Oracle Cloud Infrastructure Identity service.
 *
 * **Deprecated.** For more information, see [Deprecated IAM Service APIs](https://docs.cloud.oracle.com/iaas/Content/Identity/Reference/deprecatediamapis.htm).
 *
 * Creates a single mapping between an IdP group and an IAM Service
 * [group](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/Group/).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testIdpGroupMapping = new oci.identity.IdpGroupMapping("test_idp_group_mapping", {
 *     groupId: testGroup.id,
 *     identityProviderId: testIdentityProvider.id,
 *     idpGroupName: idpGroupMappingIdpGroupName,
 * });
 * ```
 *
 * ## Import
 *
 * IdpGroupMappings can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Identity/idpGroupMapping:IdpGroupMapping test_idp_group_mapping "identityProviders/{identityProviderId}/groupMappings/{mappingId}"
 * ```
 */
export class IdpGroupMapping extends pulumi.CustomResource {
    /**
     * Get an existing IdpGroupMapping resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: IdpGroupMappingState, opts?: pulumi.CustomResourceOptions): IdpGroupMapping {
        return new IdpGroupMapping(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Identity/idpGroupMapping:IdpGroupMapping';

    /**
     * Returns true if the given object is an instance of IdpGroupMapping.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is IdpGroupMapping {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === IdpGroupMapping.__pulumiType;
    }

    /**
     * The OCID of the tenancy containing the `IdentityProvider`.
     */
    public /*out*/ readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) The OCID of the IAM Service [group](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/Group/) you want to map to the IdP group.
     */
    public readonly groupId!: pulumi.Output<string>;
    /**
     * The OCID of the identity provider.
     */
    public readonly identityProviderId!: pulumi.Output<string>;
    /**
     * (Updatable) The name of the IdP group you want to map.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly idpGroupName!: pulumi.Output<string>;
    /**
     * The detailed status of INACTIVE lifecycleState.
     */
    public /*out*/ readonly inactiveState!: pulumi.Output<string>;
    /**
     * The mapping's current state.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Date and time the mapping was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;

    /**
     * Create a IdpGroupMapping resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: IdpGroupMappingArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: IdpGroupMappingArgs | IdpGroupMappingState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as IdpGroupMappingState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["groupId"] = state ? state.groupId : undefined;
            resourceInputs["identityProviderId"] = state ? state.identityProviderId : undefined;
            resourceInputs["idpGroupName"] = state ? state.idpGroupName : undefined;
            resourceInputs["inactiveState"] = state ? state.inactiveState : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
        } else {
            const args = argsOrState as IdpGroupMappingArgs | undefined;
            if ((!args || args.groupId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'groupId'");
            }
            if ((!args || args.identityProviderId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'identityProviderId'");
            }
            if ((!args || args.idpGroupName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'idpGroupName'");
            }
            resourceInputs["groupId"] = args ? args.groupId : undefined;
            resourceInputs["identityProviderId"] = args ? args.identityProviderId : undefined;
            resourceInputs["idpGroupName"] = args ? args.idpGroupName : undefined;
            resourceInputs["compartmentId"] = undefined /*out*/;
            resourceInputs["inactiveState"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(IdpGroupMapping.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering IdpGroupMapping resources.
 */
export interface IdpGroupMappingState {
    /**
     * The OCID of the tenancy containing the `IdentityProvider`.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the IAM Service [group](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/Group/) you want to map to the IdP group.
     */
    groupId?: pulumi.Input<string>;
    /**
     * The OCID of the identity provider.
     */
    identityProviderId?: pulumi.Input<string>;
    /**
     * (Updatable) The name of the IdP group you want to map.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    idpGroupName?: pulumi.Input<string>;
    /**
     * The detailed status of INACTIVE lifecycleState.
     */
    inactiveState?: pulumi.Input<string>;
    /**
     * The mapping's current state.
     */
    state?: pulumi.Input<string>;
    /**
     * Date and time the mapping was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a IdpGroupMapping resource.
 */
export interface IdpGroupMappingArgs {
    /**
     * (Updatable) The OCID of the IAM Service [group](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/Group/) you want to map to the IdP group.
     */
    groupId: pulumi.Input<string>;
    /**
     * The OCID of the identity provider.
     */
    identityProviderId: pulumi.Input<string>;
    /**
     * (Updatable) The name of the IdP group you want to map.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    idpGroupName: pulumi.Input<string>;
}
