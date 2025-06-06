// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Execution Action resource in Oracle Cloud Infrastructure Database service.
 *
 * Gets information about the specified execution action.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExecutionAction = oci.Database.getExecutionAction({
 *     executionActionId: testExecutionActionOciDatabaseExecutionAction.id,
 * });
 * ```
 */
export function getExecutionAction(args: GetExecutionActionArgs, opts?: pulumi.InvokeOptions): Promise<GetExecutionActionResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Database/getExecutionAction:getExecutionAction", {
        "executionActionId": args.executionActionId,
    }, opts);
}

/**
 * A collection of arguments for invoking getExecutionAction.
 */
export interface GetExecutionActionArgs {
    /**
     * The execution action [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    executionActionId: string;
}

/**
 * A collection of values returned by getExecutionAction.
 */
export interface GetExecutionActionResult {
    /**
     * List of action members of this execution action.
     */
    readonly actionMembers: outputs.Database.GetExecutionActionActionMember[];
    /**
     * Map<ParamName, ParamValue> where a key value pair describes the specific action parameter. Example: `{"count": "3"}`
     */
    readonly actionParams: {[key: string]: string};
    /**
     * The action type of the execution action being performed
     */
    readonly actionType: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    readonly definedTags: {[key: string]: string};
    /**
     * Description of the execution action.
     */
    readonly description: string;
    /**
     * The user-friendly name for the execution action. The name does not need to be unique.
     */
    readonly displayName: string;
    /**
     * The estimated time of the execution action in minutes.
     */
    readonly estimatedTimeInMins: number;
    readonly executionActionId: string;
    /**
     * The priority order of the execution action.
     */
    readonly executionActionOrder: number;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the execution window resource the execution action belongs to.
     */
    readonly executionWindowId: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the execution action.
     */
    readonly id: string;
    /**
     * Additional information about the current lifecycle state.
     */
    readonly lifecycleDetails: string;
    /**
     * The current sub-state of the execution action. Valid states are DURATION_EXCEEDED, MAINTENANCE_IN_PROGRESS and WAITING.
     */
    readonly lifecycleSubstate: string;
    /**
     * The current state of the execution action. Valid states are SCHEDULED, IN_PROGRESS, FAILED, CANCELED, UPDATING, DELETED, SUCCEEDED and PARTIAL_SUCCESS.
     */
    readonly state: string;
    /**
     * The date and time the execution action was created.
     */
    readonly timeCreated: string;
    /**
     * The last date and time that the execution action was updated.
     */
    readonly timeUpdated: string;
    /**
     * The total time taken by corresponding resource activity in minutes.
     */
    readonly totalTimeTakenInMins: number;
}
/**
 * This data source provides details about a specific Execution Action resource in Oracle Cloud Infrastructure Database service.
 *
 * Gets information about the specified execution action.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExecutionAction = oci.Database.getExecutionAction({
 *     executionActionId: testExecutionActionOciDatabaseExecutionAction.id,
 * });
 * ```
 */
export function getExecutionActionOutput(args: GetExecutionActionOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetExecutionActionResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Database/getExecutionAction:getExecutionAction", {
        "executionActionId": args.executionActionId,
    }, opts);
}

/**
 * A collection of arguments for invoking getExecutionAction.
 */
export interface GetExecutionActionOutputArgs {
    /**
     * The execution action [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    executionActionId: pulumi.Input<string>;
}
