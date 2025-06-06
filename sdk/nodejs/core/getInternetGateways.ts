// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Internet Gateways in Oracle Cloud Infrastructure Core service.
 *
 * Lists the internet gateways in the specified VCN and the specified compartment.
 * If the VCN ID is not provided, then the list includes the internet gateways from all VCNs in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testInternetGateways = oci.Core.getInternetGateways({
 *     compartmentId: compartmentId,
 *     displayName: internetGatewayDisplayName,
 *     state: internetGatewayState,
 *     vcnId: testVcn.id,
 * });
 * ```
 */
export function getInternetGateways(args: GetInternetGatewaysArgs, opts?: pulumi.InvokeOptions): Promise<GetInternetGatewaysResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Core/getInternetGateways:getInternetGateways", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
        "vcnId": args.vcnId,
    }, opts);
}

/**
 * A collection of arguments for invoking getInternetGateways.
 */
export interface GetInternetGatewaysArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: string;
    filters?: inputs.Core.GetInternetGatewaysFilter[];
    /**
     * A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
     */
    state?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
     */
    vcnId?: string;
}

/**
 * A collection of values returned by getInternetGateways.
 */
export interface GetInternetGatewaysResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the internet gateway.
     */
    readonly compartmentId: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly filters?: outputs.Core.GetInternetGatewaysFilter[];
    /**
     * The list of gateways.
     */
    readonly gateways: outputs.Core.GetInternetGatewaysGateway[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The internet gateway's current state.
     */
    readonly state?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the Internet Gateway belongs to.
     */
    readonly vcnId?: string;
}
/**
 * This data source provides the list of Internet Gateways in Oracle Cloud Infrastructure Core service.
 *
 * Lists the internet gateways in the specified VCN and the specified compartment.
 * If the VCN ID is not provided, then the list includes the internet gateways from all VCNs in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testInternetGateways = oci.Core.getInternetGateways({
 *     compartmentId: compartmentId,
 *     displayName: internetGatewayDisplayName,
 *     state: internetGatewayState,
 *     vcnId: testVcn.id,
 * });
 * ```
 */
export function getInternetGatewaysOutput(args: GetInternetGatewaysOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetInternetGatewaysResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Core/getInternetGateways:getInternetGateways", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
        "vcnId": args.vcnId,
    }, opts);
}

/**
 * A collection of arguments for invoking getInternetGateways.
 */
export interface GetInternetGatewaysOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Core.GetInternetGatewaysFilterArgs>[]>;
    /**
     * A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
     */
    state?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
     */
    vcnId?: pulumi.Input<string>;
}
