// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Drg Route Table Route Rules in Oracle Cloud Infrastructure Core service.
 *
 * Lists the route rules in the specified DRG route table.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDrgRouteTableRouteRules = oci.Core.getDrgRouteTableRouteRules({
 *     drgRouteTableId: testDrgRouteTable.id,
 *     routeType: drgRouteTableRouteRuleRouteType,
 * });
 * ```
 */
export function getDrgRouteTableRouteRules(args: GetDrgRouteTableRouteRulesArgs, opts?: pulumi.InvokeOptions): Promise<GetDrgRouteTableRouteRulesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Core/getDrgRouteTableRouteRules:getDrgRouteTableRouteRules", {
        "drgRouteTableId": args.drgRouteTableId,
        "filters": args.filters,
        "routeType": args.routeType,
    }, opts);
}

/**
 * A collection of arguments for invoking getDrgRouteTableRouteRules.
 */
export interface GetDrgRouteTableRouteRulesArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table.
     */
    drgRouteTableId: string;
    filters?: inputs.Core.GetDrgRouteTableRouteRulesFilter[];
    /**
     * Static routes are specified through the DRG route table API. Dynamic routes are learned by the DRG from the DRG attachments through various routing protocols.
     */
    routeType?: string;
}

/**
 * A collection of values returned by getDrgRouteTableRouteRules.
 */
export interface GetDrgRouteTableRouteRulesResult {
    /**
     * The list of drg_route_rules.
     */
    readonly drgRouteRules: outputs.Core.GetDrgRouteTableRouteRulesDrgRouteRule[];
    readonly drgRouteTableId: string;
    readonly filters?: outputs.Core.GetDrgRouteTableRouteRulesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * You can specify static routes for the DRG route table using the API. The DRG learns dynamic routes from the DRG attachments using various routing protocols.
     */
    readonly routeType?: string;
}
/**
 * This data source provides the list of Drg Route Table Route Rules in Oracle Cloud Infrastructure Core service.
 *
 * Lists the route rules in the specified DRG route table.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDrgRouteTableRouteRules = oci.Core.getDrgRouteTableRouteRules({
 *     drgRouteTableId: testDrgRouteTable.id,
 *     routeType: drgRouteTableRouteRuleRouteType,
 * });
 * ```
 */
export function getDrgRouteTableRouteRulesOutput(args: GetDrgRouteTableRouteRulesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDrgRouteTableRouteRulesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Core/getDrgRouteTableRouteRules:getDrgRouteTableRouteRules", {
        "drgRouteTableId": args.drgRouteTableId,
        "filters": args.filters,
        "routeType": args.routeType,
    }, opts);
}

/**
 * A collection of arguments for invoking getDrgRouteTableRouteRules.
 */
export interface GetDrgRouteTableRouteRulesOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table.
     */
    drgRouteTableId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Core.GetDrgRouteTableRouteRulesFilterArgs>[]>;
    /**
     * Static routes are specified through the DRG route table API. Dynamic routes are learned by the DRG from the DRG attachments through various routing protocols.
     */
    routeType?: pulumi.Input<string>;
}
