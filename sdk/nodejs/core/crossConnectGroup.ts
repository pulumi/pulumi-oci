// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Cross Connect Group resource in Oracle Cloud Infrastructure Core service.
 *
 * Creates a new cross-connect group to use with Oracle Cloud Infrastructure
 * FastConnect. For more information, see
 * [FastConnect Overview](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/fastconnect.htm).
 *
 * For the purposes of access control, you must provide the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the
 * compartment where you want the cross-connect group to reside. If you're
 * not sure which compartment to use, put the cross-connect group in the
 * same compartment with your VCN. For more information about
 * compartments and access control, see
 * [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
 * For information about OCIDs, see
 * [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
 *
 * You may optionally specify a *display name* for the cross-connect group.
 * It does not have to be unique, and you can change it. Avoid entering confidential information.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCrossConnectGroup = new oci.core.CrossConnectGroup("testCrossConnectGroup", {
 *     compartmentId: _var.compartment_id,
 *     customerReferenceName: _var.cross_connect_group_customer_reference_name,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     displayName: _var.cross_connect_group_display_name,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * CrossConnectGroups can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:Core/crossConnectGroup:CrossConnectGroup test_cross_connect_group "id"
 * ```
 */
export class CrossConnectGroup extends pulumi.CustomResource {
    /**
     * Get an existing CrossConnectGroup resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: CrossConnectGroupState, opts?: pulumi.CustomResourceOptions): CrossConnectGroup {
        return new CrossConnectGroup(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Core/crossConnectGroup:CrossConnectGroup';

    /**
     * Returns true if the given object is an instance of CrossConnectGroup.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is CrossConnectGroup {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === CrossConnectGroup.__pulumiType;
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the cross-connect group.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) A reference name or identifier for the physical fiber connection that this cross-connect group uses.
     */
    public readonly customerReferenceName!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * Properties used for MACsec (if capable).
     */
    public readonly macsecProperties!: pulumi.Output<outputs.Core.CrossConnectGroupMacsecProperties>;
    /**
     * The FastConnect device that terminates the logical connection. This device might be different than the device that terminates the physical connection.
     */
    public /*out*/ readonly ociLogicalDeviceName!: pulumi.Output<string>;
    /**
     * The FastConnect device that terminates the physical connection.
     */
    public /*out*/ readonly ociPhysicalDeviceName!: pulumi.Output<string>;
    /**
     * The cross-connect group's current state.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the cross-connect group was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;

    /**
     * Create a CrossConnectGroup resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: CrossConnectGroupArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: CrossConnectGroupArgs | CrossConnectGroupState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as CrossConnectGroupState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["customerReferenceName"] = state ? state.customerReferenceName : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["macsecProperties"] = state ? state.macsecProperties : undefined;
            resourceInputs["ociLogicalDeviceName"] = state ? state.ociLogicalDeviceName : undefined;
            resourceInputs["ociPhysicalDeviceName"] = state ? state.ociPhysicalDeviceName : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
        } else {
            const args = argsOrState as CrossConnectGroupArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["customerReferenceName"] = args ? args.customerReferenceName : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["macsecProperties"] = args ? args.macsecProperties : undefined;
            resourceInputs["ociLogicalDeviceName"] = undefined /*out*/;
            resourceInputs["ociPhysicalDeviceName"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(CrossConnectGroup.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering CrossConnectGroup resources.
 */
export interface CrossConnectGroupState {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the cross-connect group.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) A reference name or identifier for the physical fiber connection that this cross-connect group uses.
     */
    customerReferenceName?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * Properties used for MACsec (if capable).
     */
    macsecProperties?: pulumi.Input<inputs.Core.CrossConnectGroupMacsecProperties>;
    /**
     * The FastConnect device that terminates the logical connection. This device might be different than the device that terminates the physical connection.
     */
    ociLogicalDeviceName?: pulumi.Input<string>;
    /**
     * The FastConnect device that terminates the physical connection.
     */
    ociPhysicalDeviceName?: pulumi.Input<string>;
    /**
     * The cross-connect group's current state.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the cross-connect group was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a CrossConnectGroup resource.
 */
export interface CrossConnectGroupArgs {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the cross-connect group.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) A reference name or identifier for the physical fiber connection that this cross-connect group uses.
     */
    customerReferenceName?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * Properties used for MACsec (if capable).
     */
    macsecProperties?: pulumi.Input<inputs.Core.CrossConnectGroupMacsecProperties>;
}