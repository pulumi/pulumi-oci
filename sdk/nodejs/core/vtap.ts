// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Vtap resource in Oracle Cloud Infrastructure Core service.
 *
 * Creates a virtual test access point (VTAP) in the specified compartment.
 *
 * For the purposes of access control, you must provide the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the VTAP.
 * For more information about compartments and access control, see
 * [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
 * For information about OCIDs, see [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
 *
 * You may optionally specify a *display name* for the VTAP, otherwise a default is provided.
 * It does not have to be unique, and you can change it.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVtap = new oci.core.Vtap("test_vtap", {
 *     captureFilterId: testCaptureFilter.id,
 *     compartmentId: compartmentId,
 *     sourceId: testSource.id,
 *     vcnId: testVcn.id,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     displayName: vtapDisplayName,
 *     encapsulationProtocol: vtapEncapsulationProtocol,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     isVtapEnabled: vtapIsVtapEnabled,
 *     maxPacketSize: vtapMaxPacketSize,
 *     sourcePrivateEndpointIp: vtapSourcePrivateEndpointIp,
 *     sourcePrivateEndpointSubnetId: testSubnet.id,
 *     sourceType: vtapSourceType,
 *     targetId: testTarget.id,
 *     targetIp: vtapTargetIp,
 *     targetType: vtapTargetType,
 *     trafficMode: vtapTrafficMode,
 *     vxlanNetworkIdentifier: vtapVxlanNetworkIdentifier,
 * });
 * ```
 *
 * ## Import
 *
 * Vtaps can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Core/vtap:Vtap test_vtap "id"
 * ```
 */
export class Vtap extends pulumi.CustomResource {
    /**
     * Get an existing Vtap resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: VtapState, opts?: pulumi.CustomResourceOptions): Vtap {
        return new Vtap(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Core/vtap:Vtap';

    /**
     * Returns true if the given object is an instance of Vtap.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Vtap {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Vtap.__pulumiType;
    }

    /**
     * (Updatable) The capture filter's Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
     */
    public readonly captureFilterId!: pulumi.Output<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the `Vtap` resource.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Defines an encapsulation header type for the VTAP's mirrored traffic.
     */
    public readonly encapsulationProtocol!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Used to start or stop a `Vtap` resource.
     * * `TRUE` directs the VTAP to start mirroring traffic.
     * * `FALSE` (Default) directs the VTAP to stop mirroring traffic.
     */
    public readonly isVtapEnabled!: pulumi.Output<boolean>;
    /**
     * The VTAP's current running state.
     */
    public /*out*/ readonly lifecycleStateDetails!: pulumi.Output<string>;
    /**
     * (Updatable) The maximum size of the packets to be included in the filter.
     */
    public readonly maxPacketSize!: pulumi.Output<number>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source point where packets are captured.
     */
    public readonly sourceId!: pulumi.Output<string>;
    /**
     * (Updatable) The IP Address of the source private endpoint.
     */
    public readonly sourcePrivateEndpointIp!: pulumi.Output<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that source private endpoint belongs to.
     */
    public readonly sourcePrivateEndpointSubnetId!: pulumi.Output<string>;
    /**
     * (Updatable) The source type for the VTAP.
     */
    public readonly sourceType!: pulumi.Output<string>;
    /**
     * The VTAP's administrative lifecycle state.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the destination resource where mirrored packets are sent.
     */
    public readonly targetId!: pulumi.Output<string>;
    /**
     * (Updatable) The IP address of the destination resource where mirrored packets are sent.
     */
    public readonly targetIp!: pulumi.Output<string>;
    /**
     * (Updatable) The target type for the VTAP.
     */
    public readonly targetType!: pulumi.Output<string>;
    /**
     * The date and time the VTAP was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2020-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * (Updatable) Used to control the priority of traffic. It is an optional field. If it not passed, the value is DEFAULT
     */
    public readonly trafficMode!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN containing the `Vtap` resource.
     */
    public readonly vcnId!: pulumi.Output<string>;
    /**
     * (Updatable) The virtual extensible LAN (VXLAN) network identifier (or VXLAN segment ID) that uniquely identifies the VXLAN. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly vxlanNetworkIdentifier!: pulumi.Output<string>;

    /**
     * Create a Vtap resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: VtapArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: VtapArgs | VtapState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as VtapState | undefined;
            resourceInputs["captureFilterId"] = state ? state.captureFilterId : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["encapsulationProtocol"] = state ? state.encapsulationProtocol : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["isVtapEnabled"] = state ? state.isVtapEnabled : undefined;
            resourceInputs["lifecycleStateDetails"] = state ? state.lifecycleStateDetails : undefined;
            resourceInputs["maxPacketSize"] = state ? state.maxPacketSize : undefined;
            resourceInputs["sourceId"] = state ? state.sourceId : undefined;
            resourceInputs["sourcePrivateEndpointIp"] = state ? state.sourcePrivateEndpointIp : undefined;
            resourceInputs["sourcePrivateEndpointSubnetId"] = state ? state.sourcePrivateEndpointSubnetId : undefined;
            resourceInputs["sourceType"] = state ? state.sourceType : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["targetId"] = state ? state.targetId : undefined;
            resourceInputs["targetIp"] = state ? state.targetIp : undefined;
            resourceInputs["targetType"] = state ? state.targetType : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["trafficMode"] = state ? state.trafficMode : undefined;
            resourceInputs["vcnId"] = state ? state.vcnId : undefined;
            resourceInputs["vxlanNetworkIdentifier"] = state ? state.vxlanNetworkIdentifier : undefined;
        } else {
            const args = argsOrState as VtapArgs | undefined;
            if ((!args || args.captureFilterId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'captureFilterId'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.sourceId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'sourceId'");
            }
            if ((!args || args.vcnId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'vcnId'");
            }
            resourceInputs["captureFilterId"] = args ? args.captureFilterId : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["encapsulationProtocol"] = args ? args.encapsulationProtocol : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["isVtapEnabled"] = args ? args.isVtapEnabled : undefined;
            resourceInputs["maxPacketSize"] = args ? args.maxPacketSize : undefined;
            resourceInputs["sourceId"] = args ? args.sourceId : undefined;
            resourceInputs["sourcePrivateEndpointIp"] = args ? args.sourcePrivateEndpointIp : undefined;
            resourceInputs["sourcePrivateEndpointSubnetId"] = args ? args.sourcePrivateEndpointSubnetId : undefined;
            resourceInputs["sourceType"] = args ? args.sourceType : undefined;
            resourceInputs["targetId"] = args ? args.targetId : undefined;
            resourceInputs["targetIp"] = args ? args.targetIp : undefined;
            resourceInputs["targetType"] = args ? args.targetType : undefined;
            resourceInputs["trafficMode"] = args ? args.trafficMode : undefined;
            resourceInputs["vcnId"] = args ? args.vcnId : undefined;
            resourceInputs["vxlanNetworkIdentifier"] = args ? args.vxlanNetworkIdentifier : undefined;
            resourceInputs["lifecycleStateDetails"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(Vtap.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Vtap resources.
 */
export interface VtapState {
    /**
     * (Updatable) The capture filter's Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
     */
    captureFilterId?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the `Vtap` resource.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Defines an encapsulation header type for the VTAP's mirrored traffic.
     */
    encapsulationProtocol?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Used to start or stop a `Vtap` resource.
     * * `TRUE` directs the VTAP to start mirroring traffic.
     * * `FALSE` (Default) directs the VTAP to stop mirroring traffic.
     */
    isVtapEnabled?: pulumi.Input<boolean>;
    /**
     * The VTAP's current running state.
     */
    lifecycleStateDetails?: pulumi.Input<string>;
    /**
     * (Updatable) The maximum size of the packets to be included in the filter.
     */
    maxPacketSize?: pulumi.Input<number>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source point where packets are captured.
     */
    sourceId?: pulumi.Input<string>;
    /**
     * (Updatable) The IP Address of the source private endpoint.
     */
    sourcePrivateEndpointIp?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that source private endpoint belongs to.
     */
    sourcePrivateEndpointSubnetId?: pulumi.Input<string>;
    /**
     * (Updatable) The source type for the VTAP.
     */
    sourceType?: pulumi.Input<string>;
    /**
     * The VTAP's administrative lifecycle state.
     */
    state?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the destination resource where mirrored packets are sent.
     */
    targetId?: pulumi.Input<string>;
    /**
     * (Updatable) The IP address of the destination resource where mirrored packets are sent.
     */
    targetIp?: pulumi.Input<string>;
    /**
     * (Updatable) The target type for the VTAP.
     */
    targetType?: pulumi.Input<string>;
    /**
     * The date and time the VTAP was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2020-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * (Updatable) Used to control the priority of traffic. It is an optional field. If it not passed, the value is DEFAULT
     */
    trafficMode?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN containing the `Vtap` resource.
     */
    vcnId?: pulumi.Input<string>;
    /**
     * (Updatable) The virtual extensible LAN (VXLAN) network identifier (or VXLAN segment ID) that uniquely identifies the VXLAN. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    vxlanNetworkIdentifier?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Vtap resource.
 */
export interface VtapArgs {
    /**
     * (Updatable) The capture filter's Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
     */
    captureFilterId: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the `Vtap` resource.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Defines an encapsulation header type for the VTAP's mirrored traffic.
     */
    encapsulationProtocol?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Used to start or stop a `Vtap` resource.
     * * `TRUE` directs the VTAP to start mirroring traffic.
     * * `FALSE` (Default) directs the VTAP to stop mirroring traffic.
     */
    isVtapEnabled?: pulumi.Input<boolean>;
    /**
     * (Updatable) The maximum size of the packets to be included in the filter.
     */
    maxPacketSize?: pulumi.Input<number>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source point where packets are captured.
     */
    sourceId: pulumi.Input<string>;
    /**
     * (Updatable) The IP Address of the source private endpoint.
     */
    sourcePrivateEndpointIp?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that source private endpoint belongs to.
     */
    sourcePrivateEndpointSubnetId?: pulumi.Input<string>;
    /**
     * (Updatable) The source type for the VTAP.
     */
    sourceType?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the destination resource where mirrored packets are sent.
     */
    targetId?: pulumi.Input<string>;
    /**
     * (Updatable) The IP address of the destination resource where mirrored packets are sent.
     */
    targetIp?: pulumi.Input<string>;
    /**
     * (Updatable) The target type for the VTAP.
     */
    targetType?: pulumi.Input<string>;
    /**
     * (Updatable) Used to control the priority of traffic. It is an optional field. If it not passed, the value is DEFAULT
     */
    trafficMode?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN containing the `Vtap` resource.
     */
    vcnId: pulumi.Input<string>;
    /**
     * (Updatable) The virtual extensible LAN (VXLAN) network identifier (or VXLAN segment ID) that uniquely identifies the VXLAN. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    vxlanNetworkIdentifier?: pulumi.Input<string>;
}
