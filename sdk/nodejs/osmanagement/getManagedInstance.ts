// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Managed Instance resource in Oracle Cloud Infrastructure OS Management service.
 *
 * Returns a specific Managed Instance.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedInstance = oci.OsManagement.getManagedInstance({
 *     managedInstanceId: oci_osmanagement_managed_instance.test_managed_instance.id,
 * });
 * ```
 */
export function getManagedInstance(args: GetManagedInstanceArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedInstanceResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:OsManagement/getManagedInstance:getManagedInstance", {
        "managedInstanceId": args.managedInstanceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedInstance.
 */
export interface GetManagedInstanceArgs {
    /**
     * OCID for the managed instance
     */
    managedInstanceId: string;
}

/**
 * A collection of values returned by getManagedInstance.
 */
export interface GetManagedInstanceResult {
    /**
     * if present, indicates the Managed Instance is an autonomous instance. Holds all the Autonomous specific information
     */
    readonly autonomouses: outputs.OsManagement.GetManagedInstanceAutonomouse[];
    /**
     * Number of bug fix type updates available to be installed
     */
    readonly bugUpdatesAvailable: number;
    /**
     * list of child Software Sources attached to the Managed Instance
     */
    readonly childSoftwareSources: outputs.OsManagement.GetManagedInstanceChildSoftwareSource[];
    /**
     * OCID for the Compartment
     */
    readonly compartmentId: string;
    /**
     * Information specified by the user about the managed instance
     */
    readonly description: string;
    /**
     * User friendly name
     */
    readonly displayName: string;
    /**
     * Number of enhancement type updates available to be installed
     */
    readonly enhancementUpdatesAvailable: number;
    /**
     * software source identifier
     */
    readonly id: string;
    /**
     * True if user allow data collection for this instance
     */
    readonly isDataCollectionAuthorized: boolean;
    /**
     * Indicates whether a reboot is required to complete installation of updates.
     */
    readonly isRebootRequired: boolean;
    /**
     * The ksplice effective kernel version
     */
    readonly kspliceEffectiveKernelVersion: string;
    /**
     * Time at which the instance last booted
     */
    readonly lastBoot: string;
    /**
     * Time at which the instance last checked in
     */
    readonly lastCheckin: string;
    /**
     * The ids of the managed instance groups of which this instance is a member.
     */
    readonly managedInstanceGroups: outputs.OsManagement.GetManagedInstanceManagedInstanceGroup[];
    readonly managedInstanceId: string;
    /**
     * OCID of the ONS topic used to send notification to users
     */
    readonly notificationTopicId: string;
    /**
     * The Operating System type of the managed instance.
     */
    readonly osFamily: string;
    /**
     * Operating System Kernel Version
     */
    readonly osKernelVersion: string;
    /**
     * Operating System Name
     */
    readonly osName: string;
    /**
     * Operating System Version
     */
    readonly osVersion: string;
    /**
     * Number of non-classified updates available to be installed
     */
    readonly otherUpdatesAvailable: number;
    /**
     * the parent (base) Software Source attached to the Managed Instance
     */
    readonly parentSoftwareSources: outputs.OsManagement.GetManagedInstanceParentSoftwareSource[];
    /**
     * Number of scheduled jobs associated with this instance
     */
    readonly scheduledJobCount: number;
    /**
     * Number of security type updates available to be installed
     */
    readonly securityUpdatesAvailable: number;
    /**
     * status of the managed instance.
     */
    readonly status: string;
    /**
     * Number of updates available to be installed
     */
    readonly updatesAvailable: number;
    /**
     * Number of work requests associated with this instance
     */
    readonly workRequestCount: number;
}

export function getManagedInstanceOutput(args: GetManagedInstanceOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetManagedInstanceResult> {
    return pulumi.output(args).apply(a => getManagedInstance(a, opts))
}

/**
 * A collection of arguments for invoking getManagedInstance.
 */
export interface GetManagedInstanceOutputArgs {
    /**
     * OCID for the managed instance
     */
    managedInstanceId: pulumi.Input<string>;
}