// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Managed Instances in Oracle Cloud Infrastructure OS Management service.
 *
 * Returns a list of all Managed Instances.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedInstances = oci.OsManagement.getManagedInstances({
 *     compartmentId: compartmentId,
 *     displayName: managedInstanceDisplayName,
 *     osFamily: managedInstanceOsFamily,
 * });
 * ```
 */
export function getManagedInstances(args: GetManagedInstancesArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedInstancesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:OsManagement/getManagedInstances:getManagedInstances", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "osFamily": args.osFamily,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedInstances.
 */
export interface GetManagedInstancesArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
     */
    displayName?: string;
    filters?: inputs.OsManagement.GetManagedInstancesFilter[];
    /**
     * The OS family for which to list resources.
     */
    osFamily?: string;
}

/**
 * A collection of values returned by getManagedInstances.
 */
export interface GetManagedInstancesResult {
    /**
     * OCID for the Compartment
     */
    readonly compartmentId: string;
    /**
     * User friendly name
     */
    readonly displayName?: string;
    readonly filters?: outputs.OsManagement.GetManagedInstancesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of managed_instances.
     */
    readonly managedInstances: outputs.OsManagement.GetManagedInstancesManagedInstance[];
    /**
     * The Operating System type of the managed instance.
     */
    readonly osFamily?: string;
}
/**
 * This data source provides the list of Managed Instances in Oracle Cloud Infrastructure OS Management service.
 *
 * Returns a list of all Managed Instances.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedInstances = oci.OsManagement.getManagedInstances({
 *     compartmentId: compartmentId,
 *     displayName: managedInstanceDisplayName,
 *     osFamily: managedInstanceOsFamily,
 * });
 * ```
 */
export function getManagedInstancesOutput(args: GetManagedInstancesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetManagedInstancesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:OsManagement/getManagedInstances:getManagedInstances", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "osFamily": args.osFamily,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedInstances.
 */
export interface GetManagedInstancesOutputArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.OsManagement.GetManagedInstancesFilterArgs>[]>;
    /**
     * The OS family for which to list resources.
     */
    osFamily?: pulumi.Input<string>;
}
