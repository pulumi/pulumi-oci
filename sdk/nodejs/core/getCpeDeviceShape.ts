// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Cpe Device Shape resource in Oracle Cloud Infrastructure Core service.
 *
 * Gets the detailed information about the specified CPE device type. This might include a set of questions
 * that are specific to the particular CPE device type. The customer must supply answers to those questions
 * (see [UpdateTunnelCpeDeviceConfig](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/TunnelCpeDeviceConfig/UpdateTunnelCpeDeviceConfig)).
 * The service merges the answers with a template of other information for the CPE device type. The following
 * operations return the merged content:
 *
 *   * [GetCpeDeviceConfigContent](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/GetCpeDeviceConfigContent)
 *   * [GetIpsecCpeDeviceConfigContent](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/IPSecConnection/GetIpsecCpeDeviceConfigContent)
 *   * [GetTunnelCpeDeviceConfigContent](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/TunnelCpeDeviceConfig/GetTunnelCpeDeviceConfigContent)
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCpeDeviceShape = oci.Core.getCpeDeviceShape({
 *     cpeDeviceShapeId: testCpeDeviceShapeOciCoreCpeDeviceShape.id,
 * });
 * ```
 */
export function getCpeDeviceShape(args: GetCpeDeviceShapeArgs, opts?: pulumi.InvokeOptions): Promise<GetCpeDeviceShapeResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Core/getCpeDeviceShape:getCpeDeviceShape", {
        "cpeDeviceShapeId": args.cpeDeviceShapeId,
    }, opts);
}

/**
 * A collection of arguments for invoking getCpeDeviceShape.
 */
export interface GetCpeDeviceShapeArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CPE device shape.
     */
    cpeDeviceShapeId: string;
}

/**
 * A collection of values returned by getCpeDeviceShape.
 */
export interface GetCpeDeviceShapeResult {
    /**
     * Basic information about a particular CPE device type.
     */
    readonly cpeDeviceInfos: outputs.Core.GetCpeDeviceShapeCpeDeviceInfo[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CPE device shape. This value uniquely identifies the type of CPE device.
     */
    readonly cpeDeviceShapeId: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * For certain CPE devices types, the customer can provide answers to questions that are specific to the device type. This attribute contains a list of those questions. The Networking service merges the answers with other information and renders a set of CPE configuration content. To provide the answers, use [UpdateTunnelCpeDeviceConfig](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/TunnelCpeDeviceConfig/UpdateTunnelCpeDeviceConfig).
     */
    readonly parameters: outputs.Core.GetCpeDeviceShapeParameter[];
    /**
     * A template of CPE device configuration information that will be merged with the customer's answers to the questions to render the final CPE device configuration content. Also see:
     * * [GetCpeDeviceConfigContent](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/GetCpeDeviceConfigContent)
     * * [GetIpsecCpeDeviceConfigContent](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/IPSecConnection/GetIpsecCpeDeviceConfigContent)
     * * [GetTunnelCpeDeviceConfigContent](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/TunnelCpeDeviceConfig/GetTunnelCpeDeviceConfigContent)
     */
    readonly template: string;
}
/**
 * This data source provides details about a specific Cpe Device Shape resource in Oracle Cloud Infrastructure Core service.
 *
 * Gets the detailed information about the specified CPE device type. This might include a set of questions
 * that are specific to the particular CPE device type. The customer must supply answers to those questions
 * (see [UpdateTunnelCpeDeviceConfig](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/TunnelCpeDeviceConfig/UpdateTunnelCpeDeviceConfig)).
 * The service merges the answers with a template of other information for the CPE device type. The following
 * operations return the merged content:
 *
 *   * [GetCpeDeviceConfigContent](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/GetCpeDeviceConfigContent)
 *   * [GetIpsecCpeDeviceConfigContent](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/IPSecConnection/GetIpsecCpeDeviceConfigContent)
 *   * [GetTunnelCpeDeviceConfigContent](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/TunnelCpeDeviceConfig/GetTunnelCpeDeviceConfigContent)
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCpeDeviceShape = oci.Core.getCpeDeviceShape({
 *     cpeDeviceShapeId: testCpeDeviceShapeOciCoreCpeDeviceShape.id,
 * });
 * ```
 */
export function getCpeDeviceShapeOutput(args: GetCpeDeviceShapeOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetCpeDeviceShapeResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Core/getCpeDeviceShape:getCpeDeviceShape", {
        "cpeDeviceShapeId": args.cpeDeviceShapeId,
    }, opts);
}

/**
 * A collection of arguments for invoking getCpeDeviceShape.
 */
export interface GetCpeDeviceShapeOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CPE device shape.
     */
    cpeDeviceShapeId: pulumi.Input<string>;
}
