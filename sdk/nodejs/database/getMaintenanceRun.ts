// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Maintenance Run resource in Oracle Cloud Infrastructure Database service.
 *
 * Gets information about the specified maintenance run.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMaintenanceRun = oci.Database.getMaintenanceRun({
 *     maintenanceRunId: testMaintenanceRunOciDatabaseMaintenanceRun.id,
 * });
 * ```
 */
export function getMaintenanceRun(args: GetMaintenanceRunArgs, opts?: pulumi.InvokeOptions): Promise<GetMaintenanceRunResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Database/getMaintenanceRun:getMaintenanceRun", {
        "maintenanceRunId": args.maintenanceRunId,
    }, opts);
}

/**
 * A collection of arguments for invoking getMaintenanceRun.
 */
export interface GetMaintenanceRunArgs {
    /**
     * The maintenance run OCID.
     */
    maintenanceRunId: string;
}

/**
 * A collection of values returned by getMaintenanceRun.
 */
export interface GetMaintenanceRunResult {
    /**
     * The OCID of the compartment.
     */
    readonly compartmentId: string;
    /**
     * Extend current custom action timeout between the current database servers during waiting state, from 0 (zero) to 30 minutes.
     */
    readonly currentCustomActionTimeoutInMins: number;
    /**
     * The name of the current infrastruture component that is getting patched.
     */
    readonly currentPatchingComponent: string;
    /**
     * Determines the amount of time the system will wait before the start of each database server patching operation. Specify a number of minutes, from 15 to 120.
     */
    readonly customActionTimeoutInMins: number;
    /**
     * The Autonomous Database Software Image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     */
    readonly databaseSoftwareImageId: string;
    /**
     * Description of the maintenance run.
     */
    readonly description: string;
    /**
     * The user-friendly name for the maintenance run.
     */
    readonly displayName: string;
    /**
     * The estimated start time of the next infrastruture component patching operation.
     */
    readonly estimatedComponentPatchingStartTime: string;
    /**
     * The estimated total time required in minutes for all patching operations (database server, storage server, and network switch patching).
     */
    readonly estimatedPatchingTimes: outputs.Database.GetMaintenanceRunEstimatedPatchingTime[];
    /**
     * The OCID of the maintenance run.
     */
    readonly id: string;
    /**
     * If true, enables the configuration of a custom action timeout (waiting period) between database servers patching operations.
     */
    readonly isCustomActionTimeoutEnabled: boolean;
    /**
     * Indicates if an automatic DST Time Zone file update is enabled for the Autonomous Container Database. If enabled along with Release Update, patching will be done in a Non-Rolling manner.
     */
    readonly isDstFileUpdateEnabled: boolean;
    /**
     * If `FALSE`, the maintenance run doesn't support granular maintenance.
     */
    readonly isMaintenanceRunGranular: boolean;
    /**
     * Additional information about the current lifecycle state.
     */
    readonly lifecycleDetails: string;
    readonly maintenanceRunId: string;
    /**
     * Maintenance sub-type.
     */
    readonly maintenanceSubtype: string;
    /**
     * Maintenance type.
     */
    readonly maintenanceType: string;
    /**
     * Contain the patch failure count.
     */
    readonly patchFailureCount: number;
    /**
     * The unique identifier of the patch. The identifier string includes the patch type, the Oracle Database version, and the patch creation date (using the format YYMMDD). For example, the identifier `ru_patch_19.9.0.0_201030` is used for an RU patch for Oracle Database 19.9.0.0 that was released October 30, 2020.
     */
    readonly patchId: string;
    readonly patchType: string;
    /**
     * The time when the patching operation ended.
     */
    readonly patchingEndTime: string;
    /**
     * Cloud Exadata infrastructure node patching method, either "ROLLING" or "NONROLLING". Default value is ROLLING.
     */
    readonly patchingMode: string;
    /**
     * The time when the patching operation started.
     */
    readonly patchingStartTime: string;
    /**
     * The status of the patching operation.
     */
    readonly patchingStatus: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the maintenance run for the Autonomous Data Guard association's peer container database.
     */
    readonly peerMaintenanceRunId: string;
    /**
     * The list of OCIDs for the maintenance runs associated with their Autonomous Data Guard peer container databases.
     */
    readonly peerMaintenanceRunIds: string[];
    /**
     * The current state of the maintenance run. For Autonomous Database Serverless instances, valid states are IN_PROGRESS, SUCCEEDED, and FAILED.
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The target software version for the database server patching operation.
     */
    readonly targetDbServerVersion: string;
    /**
     * The ID of the target resource on which the maintenance run occurs.
     */
    readonly targetResourceId: string;
    /**
     * The type of the target resource on which the maintenance run occurs.
     */
    readonly targetResourceType: string;
    /**
     * The target Cell version that is to be patched to.
     */
    readonly targetStorageServerVersion: string;
    /**
     * The date and time the maintenance run was completed.
     */
    readonly timeEnded: string;
    /**
     * The date and time the maintenance run is scheduled to occur.
     */
    readonly timeScheduled: string;
    /**
     * The date and time the maintenance run starts.
     */
    readonly timeStarted: string;
    /**
     * The total time taken by corresponding resource activity in minutes.
     */
    readonly totalTimeTakenInMins: number;
}
/**
 * This data source provides details about a specific Maintenance Run resource in Oracle Cloud Infrastructure Database service.
 *
 * Gets information about the specified maintenance run.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMaintenanceRun = oci.Database.getMaintenanceRun({
 *     maintenanceRunId: testMaintenanceRunOciDatabaseMaintenanceRun.id,
 * });
 * ```
 */
export function getMaintenanceRunOutput(args: GetMaintenanceRunOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetMaintenanceRunResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Database/getMaintenanceRun:getMaintenanceRun", {
        "maintenanceRunId": args.maintenanceRunId,
    }, opts);
}

/**
 * A collection of arguments for invoking getMaintenanceRun.
 */
export interface GetMaintenanceRunOutputArgs {
    /**
     * The maintenance run OCID.
     */
    maintenanceRunId: pulumi.Input<string>;
}
