// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Management Agent Available Histories in Oracle Cloud Infrastructure Management Agent service.
 *
 * Lists the availability history records of Management Agent
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagementAgentAvailableHistories = oci.ManagementAgent.getManagementAgentAvailableHistories({
 *     managementAgentId: testManagementAgent.id,
 *     timeAvailabilityStatusEndedGreaterThan: managementAgentAvailableHistoryTimeAvailabilityStatusEndedGreaterThan,
 *     timeAvailabilityStatusStartedLessThan: managementAgentAvailableHistoryTimeAvailabilityStatusStartedLessThan,
 * });
 * ```
 */
export function getManagementAgentAvailableHistories(args: GetManagementAgentAvailableHistoriesArgs, opts?: pulumi.InvokeOptions): Promise<GetManagementAgentAvailableHistoriesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:ManagementAgent/getManagementAgentAvailableHistories:getManagementAgentAvailableHistories", {
        "filters": args.filters,
        "managementAgentId": args.managementAgentId,
        "timeAvailabilityStatusEndedGreaterThan": args.timeAvailabilityStatusEndedGreaterThan,
        "timeAvailabilityStatusStartedLessThan": args.timeAvailabilityStatusStartedLessThan,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagementAgentAvailableHistories.
 */
export interface GetManagementAgentAvailableHistoriesArgs {
    filters?: inputs.ManagementAgent.GetManagementAgentAvailableHistoriesFilter[];
    /**
     * Unique Management Agent identifier
     */
    managementAgentId: string;
    /**
     * Filter to limit the availability history results to that of time after the input time including the boundary record. Defaulted to current date minus one year. The date and time to be given as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 5.6.
     */
    timeAvailabilityStatusEndedGreaterThan?: string;
    /**
     * Filter to limit the availability history results to that of time before the input time including the boundary record Defaulted to current date. The date and time to be given as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 5.6.
     */
    timeAvailabilityStatusStartedLessThan?: string;
}

/**
 * A collection of values returned by getManagementAgentAvailableHistories.
 */
export interface GetManagementAgentAvailableHistoriesResult {
    /**
     * The list of availability_histories.
     */
    readonly availabilityHistories: outputs.ManagementAgent.GetManagementAgentAvailableHistoriesAvailabilityHistory[];
    readonly filters?: outputs.ManagementAgent.GetManagementAgentAvailableHistoriesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * agent identifier
     */
    readonly managementAgentId: string;
    readonly timeAvailabilityStatusEndedGreaterThan?: string;
    readonly timeAvailabilityStatusStartedLessThan?: string;
}
/**
 * This data source provides the list of Management Agent Available Histories in Oracle Cloud Infrastructure Management Agent service.
 *
 * Lists the availability history records of Management Agent
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagementAgentAvailableHistories = oci.ManagementAgent.getManagementAgentAvailableHistories({
 *     managementAgentId: testManagementAgent.id,
 *     timeAvailabilityStatusEndedGreaterThan: managementAgentAvailableHistoryTimeAvailabilityStatusEndedGreaterThan,
 *     timeAvailabilityStatusStartedLessThan: managementAgentAvailableHistoryTimeAvailabilityStatusStartedLessThan,
 * });
 * ```
 */
export function getManagementAgentAvailableHistoriesOutput(args: GetManagementAgentAvailableHistoriesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetManagementAgentAvailableHistoriesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:ManagementAgent/getManagementAgentAvailableHistories:getManagementAgentAvailableHistories", {
        "filters": args.filters,
        "managementAgentId": args.managementAgentId,
        "timeAvailabilityStatusEndedGreaterThan": args.timeAvailabilityStatusEndedGreaterThan,
        "timeAvailabilityStatusStartedLessThan": args.timeAvailabilityStatusStartedLessThan,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagementAgentAvailableHistories.
 */
export interface GetManagementAgentAvailableHistoriesOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.ManagementAgent.GetManagementAgentAvailableHistoriesFilterArgs>[]>;
    /**
     * Unique Management Agent identifier
     */
    managementAgentId: pulumi.Input<string>;
    /**
     * Filter to limit the availability history results to that of time after the input time including the boundary record. Defaulted to current date minus one year. The date and time to be given as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 5.6.
     */
    timeAvailabilityStatusEndedGreaterThan?: pulumi.Input<string>;
    /**
     * Filter to limit the availability history results to that of time before the input time including the boundary record Defaulted to current date. The date and time to be given as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 5.6.
     */
    timeAvailabilityStatusStartedLessThan?: pulumi.Input<string>;
}
