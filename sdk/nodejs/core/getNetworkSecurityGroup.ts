// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Network Security Group resource in Oracle Cloud Infrastructure Core service.
 *
 * Gets the specified network security group's information.
 *
 * To list the VNICs in an NSG, see
 * [ListNetworkSecurityGroupVnics](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NetworkSecurityGroupVnic/ListNetworkSecurityGroupVnics).
 *
 * To list the security rules in an NSG, see
 * [ListNetworkSecurityGroupSecurityRules](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/SecurityRule/ListNetworkSecurityGroupSecurityRules).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNetworkSecurityGroup = oci.Core.getNetworkSecurityGroup({
 *     networkSecurityGroupId: testNetworkSecurityGroupOciCoreNetworkSecurityGroup.id,
 * });
 * ```
 */
export function getNetworkSecurityGroup(args: GetNetworkSecurityGroupArgs, opts?: pulumi.InvokeOptions): Promise<GetNetworkSecurityGroupResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Core/getNetworkSecurityGroup:getNetworkSecurityGroup", {
        "networkSecurityGroupId": args.networkSecurityGroupId,
    }, opts);
}

/**
 * A collection of arguments for invoking getNetworkSecurityGroup.
 */
export interface GetNetworkSecurityGroupArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security group.
     */
    networkSecurityGroupId: string;
}

/**
 * A collection of values returned by getNetworkSecurityGroup.
 */
export interface GetNetworkSecurityGroupResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment the network security group is in.
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
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security group.
     */
    readonly id: string;
    readonly networkSecurityGroupId: string;
    /**
     * The network security group's current state.
     */
    readonly state: string;
    /**
     * The date and time the network security group was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    readonly timeCreated: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security group's VCN.
     */
    readonly vcnId: string;
}
/**
 * This data source provides details about a specific Network Security Group resource in Oracle Cloud Infrastructure Core service.
 *
 * Gets the specified network security group's information.
 *
 * To list the VNICs in an NSG, see
 * [ListNetworkSecurityGroupVnics](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NetworkSecurityGroupVnic/ListNetworkSecurityGroupVnics).
 *
 * To list the security rules in an NSG, see
 * [ListNetworkSecurityGroupSecurityRules](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/SecurityRule/ListNetworkSecurityGroupSecurityRules).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNetworkSecurityGroup = oci.Core.getNetworkSecurityGroup({
 *     networkSecurityGroupId: testNetworkSecurityGroupOciCoreNetworkSecurityGroup.id,
 * });
 * ```
 */
export function getNetworkSecurityGroupOutput(args: GetNetworkSecurityGroupOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetNetworkSecurityGroupResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Core/getNetworkSecurityGroup:getNetworkSecurityGroup", {
        "networkSecurityGroupId": args.networkSecurityGroupId,
    }, opts);
}

/**
 * A collection of arguments for invoking getNetworkSecurityGroup.
 */
export interface GetNetworkSecurityGroupOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security group.
     */
    networkSecurityGroupId: pulumi.Input<string>;
}
