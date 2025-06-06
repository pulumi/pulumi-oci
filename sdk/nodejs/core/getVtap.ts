// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Vtap resource in Oracle Cloud Infrastructure Core service.
 *
 * Gets the specified `Vtap` resource.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVtap = oci.Core.getVtap({
 *     vtapId: testVtapOciCoreVtap.id,
 * });
 * ```
 */
export function getVtap(args: GetVtapArgs, opts?: pulumi.InvokeOptions): Promise<GetVtapResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Core/getVtap:getVtap", {
        "vtapId": args.vtapId,
    }, opts);
}

/**
 * A collection of arguments for invoking getVtap.
 */
export interface GetVtapArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VTAP.
     */
    vtapId: string;
}

/**
 * A collection of values returned by getVtap.
 */
export interface GetVtapResult {
    /**
     * The capture filter's Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
     */
    readonly captureFilterId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the `Vtap` resource.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName: string;
    /**
     * Defines an encapsulation header type for the VTAP's mirrored traffic.
     */
    readonly encapsulationProtocol: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The VTAP's Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
     */
    readonly id: string;
    /**
     * Used to start or stop a `Vtap` resource.
     * * `TRUE` directs the VTAP to start mirroring traffic.
     * * `FALSE` (Default) directs the VTAP to stop mirroring traffic.
     */
    readonly isVtapEnabled: boolean;
    /**
     * The VTAP's current running state.
     */
    readonly lifecycleStateDetails: string;
    /**
     * The maximum size of the packets to be included in the filter.
     */
    readonly maxPacketSize: number;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source point where packets are captured.
     */
    readonly sourceId: string;
    /**
     * The IP Address of the source private endpoint.
     */
    readonly sourcePrivateEndpointIp: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that source private endpoint belongs to.
     */
    readonly sourcePrivateEndpointSubnetId: string;
    /**
     * The source type for the VTAP.
     */
    readonly sourceType: string;
    /**
     * The VTAP's administrative lifecycle state.
     */
    readonly state: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the destination resource where mirrored packets are sent.
     */
    readonly targetId: string;
    /**
     * The IP address of the destination resource where mirrored packets are sent.
     */
    readonly targetIp: string;
    /**
     * The target type for the VTAP.
     */
    readonly targetType: string;
    /**
     * The date and time the VTAP was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2020-08-25T21:10:29.600Z`
     */
    readonly timeCreated: string;
    /**
     * Used to control the priority of traffic. It is an optional field. If it not passed, the value is DEFAULT
     */
    readonly trafficMode: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN containing the `Vtap` resource.
     */
    readonly vcnId: string;
    readonly vtapId: string;
    /**
     * The virtual extensible LAN (VXLAN) network identifier (or VXLAN segment ID) that uniquely identifies the VXLAN.
     */
    readonly vxlanNetworkIdentifier: string;
}
/**
 * This data source provides details about a specific Vtap resource in Oracle Cloud Infrastructure Core service.
 *
 * Gets the specified `Vtap` resource.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVtap = oci.Core.getVtap({
 *     vtapId: testVtapOciCoreVtap.id,
 * });
 * ```
 */
export function getVtapOutput(args: GetVtapOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetVtapResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Core/getVtap:getVtap", {
        "vtapId": args.vtapId,
    }, opts);
}

/**
 * A collection of arguments for invoking getVtap.
 */
export interface GetVtapOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VTAP.
     */
    vtapId: pulumi.Input<string>;
}
