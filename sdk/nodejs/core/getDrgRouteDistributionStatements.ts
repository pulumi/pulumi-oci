// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Drg Route Distribution Statements in Oracle Cloud Infrastructure Core service.
 *
 * Lists the statements for the specified route distribution.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDrgRouteDistributionStatements = oci.Core.getDrgRouteDistributionStatements({
 *     drgRouteDistributionId: testDrgRouteDistribution.id,
 * });
 * ```
 */
export function getDrgRouteDistributionStatements(args: GetDrgRouteDistributionStatementsArgs, opts?: pulumi.InvokeOptions): Promise<GetDrgRouteDistributionStatementsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Core/getDrgRouteDistributionStatements:getDrgRouteDistributionStatements", {
        "drgRouteDistributionId": args.drgRouteDistributionId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getDrgRouteDistributionStatements.
 */
export interface GetDrgRouteDistributionStatementsArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route distribution.
     */
    drgRouteDistributionId: string;
    filters?: inputs.Core.GetDrgRouteDistributionStatementsFilter[];
}

/**
 * A collection of values returned by getDrgRouteDistributionStatements.
 */
export interface GetDrgRouteDistributionStatementsResult {
    readonly drgRouteDistributionId: string;
    /**
     * The list of drg_route_distribution_statements.
     */
    readonly drgRouteDistributionStatements: outputs.Core.GetDrgRouteDistributionStatementsDrgRouteDistributionStatement[];
    readonly filters?: outputs.Core.GetDrgRouteDistributionStatementsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
}
/**
 * This data source provides the list of Drg Route Distribution Statements in Oracle Cloud Infrastructure Core service.
 *
 * Lists the statements for the specified route distribution.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDrgRouteDistributionStatements = oci.Core.getDrgRouteDistributionStatements({
 *     drgRouteDistributionId: testDrgRouteDistribution.id,
 * });
 * ```
 */
export function getDrgRouteDistributionStatementsOutput(args: GetDrgRouteDistributionStatementsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDrgRouteDistributionStatementsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Core/getDrgRouteDistributionStatements:getDrgRouteDistributionStatements", {
        "drgRouteDistributionId": args.drgRouteDistributionId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getDrgRouteDistributionStatements.
 */
export interface GetDrgRouteDistributionStatementsOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route distribution.
     */
    drgRouteDistributionId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Core.GetDrgRouteDistributionStatementsFilterArgs>[]>;
}
