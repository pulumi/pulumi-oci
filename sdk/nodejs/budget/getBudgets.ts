// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Budgets in Oracle Cloud Infrastructure Budget service.
 *
 * Gets a list of budgets in a compartment.
 *
 * By default, ListBudgets returns budgets of the 'COMPARTMENT' target type, and the budget records with only one target compartment OCID.
 *
 * To list all budgets, set the targetType query parameter to ALL (for example: 'targetType=ALL').
 *
 * Clients should ignore new targetTypes, or upgrade to the latest version of the client SDK to handle new targetTypes.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBudgets = oci.Budget.getBudgets({
 *     compartmentId: tenancyOcid,
 *     displayName: budgetDisplayName,
 *     state: budgetState,
 *     targetType: budgetTargetType,
 * });
 * ```
 */
export function getBudgets(args: GetBudgetsArgs, opts?: pulumi.InvokeOptions): Promise<GetBudgetsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Budget/getBudgets:getBudgets", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
        "targetType": args.targetType,
    }, opts);
}

/**
 * A collection of arguments for invoking getBudgets.
 */
export interface GetBudgetsArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * A user-friendly name. This does not have to be unique, and it's changeable.  Example: `My new resource`
     */
    displayName?: string;
    filters?: inputs.Budget.GetBudgetsFilter[];
    /**
     * The current state of the resource to filter by.
     */
    state?: string;
    /**
     * The type of target to filter by:
     * * ALL - List all budgets
     * * COMPARTMENT - List all budgets with targetType == "COMPARTMENT"
     * * TAG - List all budgets with targetType == "TAG"
     */
    targetType?: string;
}

/**
 * A collection of values returned by getBudgets.
 */
export interface GetBudgetsResult {
    /**
     * The list of budgets.
     */
    readonly budgets: outputs.Budget.GetBudgetsBudget[];
    /**
     * The OCID of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The display name of the budget. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly filters?: outputs.Budget.GetBudgetsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current state of the budget.
     */
    readonly state?: string;
    /**
     * The type of target on which the budget is applied.
     */
    readonly targetType?: string;
}
/**
 * This data source provides the list of Budgets in Oracle Cloud Infrastructure Budget service.
 *
 * Gets a list of budgets in a compartment.
 *
 * By default, ListBudgets returns budgets of the 'COMPARTMENT' target type, and the budget records with only one target compartment OCID.
 *
 * To list all budgets, set the targetType query parameter to ALL (for example: 'targetType=ALL').
 *
 * Clients should ignore new targetTypes, or upgrade to the latest version of the client SDK to handle new targetTypes.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBudgets = oci.Budget.getBudgets({
 *     compartmentId: tenancyOcid,
 *     displayName: budgetDisplayName,
 *     state: budgetState,
 *     targetType: budgetTargetType,
 * });
 * ```
 */
export function getBudgetsOutput(args: GetBudgetsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetBudgetsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Budget/getBudgets:getBudgets", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
        "targetType": args.targetType,
    }, opts);
}

/**
 * A collection of arguments for invoking getBudgets.
 */
export interface GetBudgetsOutputArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A user-friendly name. This does not have to be unique, and it's changeable.  Example: `My new resource`
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Budget.GetBudgetsFilterArgs>[]>;
    /**
     * The current state of the resource to filter by.
     */
    state?: pulumi.Input<string>;
    /**
     * The type of target to filter by:
     * * ALL - List all budgets
     * * COMPARTMENT - List all budgets with targetType == "COMPARTMENT"
     * * TAG - List all budgets with targetType == "TAG"
     */
    targetType?: pulumi.Input<string>;
}
