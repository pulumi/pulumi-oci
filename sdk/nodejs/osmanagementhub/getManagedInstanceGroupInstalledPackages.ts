// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Managed Instance Group Installed Packages in Oracle Cloud Infrastructure Os Management Hub service.
 *
 * Lists installed packages on the specified managed instances group. Filter the list against a variety
 * of criteria including but not limited to the package name.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedInstanceGroupInstalledPackages = oci.OsManagementHub.getManagedInstanceGroupInstalledPackages({
 *     managedInstanceGroupId: testManagedInstanceGroup.id,
 *     compartmentId: compartmentId,
 *     displayNames: managedInstanceGroupInstalledPackageDisplayName,
 *     displayNameContains: managedInstanceGroupInstalledPackageDisplayNameContains,
 *     timeInstallDateEnd: managedInstanceGroupInstalledPackageTimeInstallDateEnd,
 *     timeInstallDateStart: managedInstanceGroupInstalledPackageTimeInstallDateStart,
 * });
 * ```
 */
export function getManagedInstanceGroupInstalledPackages(args: GetManagedInstanceGroupInstalledPackagesArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedInstanceGroupInstalledPackagesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:OsManagementHub/getManagedInstanceGroupInstalledPackages:getManagedInstanceGroupInstalledPackages", {
        "compartmentId": args.compartmentId,
        "displayNameContains": args.displayNameContains,
        "displayNames": args.displayNames,
        "filters": args.filters,
        "managedInstanceGroupId": args.managedInstanceGroupId,
        "timeInstallDateEnd": args.timeInstallDateEnd,
        "timeInstallDateStart": args.timeInstallDateStart,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedInstanceGroupInstalledPackages.
 */
export interface GetManagedInstanceGroupInstalledPackagesArgs {
    /**
     * The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
     */
    compartmentId?: string;
    /**
     * A filter to return resources that may partially match the given display name.
     */
    displayNameContains?: string;
    /**
     * A filter to return resources that match the given display names.
     */
    displayNames?: string[];
    filters?: inputs.OsManagementHub.GetManagedInstanceGroupInstalledPackagesFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
     */
    managedInstanceGroupId: string;
    /**
     * A filter to return only packages that were installed on or before the date provided, in ISO 8601 format.  Example: 2017-07-14T02:40:00.000Z
     */
    timeInstallDateEnd?: string;
    /**
     * The install date after which to list all packages, in ISO 8601 format  Example: 2017-07-14T02:40:00.000Z
     */
    timeInstallDateStart?: string;
}

/**
 * A collection of values returned by getManagedInstanceGroupInstalledPackages.
 */
export interface GetManagedInstanceGroupInstalledPackagesResult {
    readonly compartmentId?: string;
    readonly displayNameContains?: string;
    readonly displayNames?: string[];
    readonly filters?: outputs.OsManagementHub.GetManagedInstanceGroupInstalledPackagesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly managedInstanceGroupId: string;
    /**
     * The list of managed_instance_group_installed_package_collection.
     */
    readonly managedInstanceGroupInstalledPackageCollections: outputs.OsManagementHub.GetManagedInstanceGroupInstalledPackagesManagedInstanceGroupInstalledPackageCollection[];
    readonly timeInstallDateEnd?: string;
    readonly timeInstallDateStart?: string;
}
/**
 * This data source provides the list of Managed Instance Group Installed Packages in Oracle Cloud Infrastructure Os Management Hub service.
 *
 * Lists installed packages on the specified managed instances group. Filter the list against a variety
 * of criteria including but not limited to the package name.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedInstanceGroupInstalledPackages = oci.OsManagementHub.getManagedInstanceGroupInstalledPackages({
 *     managedInstanceGroupId: testManagedInstanceGroup.id,
 *     compartmentId: compartmentId,
 *     displayNames: managedInstanceGroupInstalledPackageDisplayName,
 *     displayNameContains: managedInstanceGroupInstalledPackageDisplayNameContains,
 *     timeInstallDateEnd: managedInstanceGroupInstalledPackageTimeInstallDateEnd,
 *     timeInstallDateStart: managedInstanceGroupInstalledPackageTimeInstallDateStart,
 * });
 * ```
 */
export function getManagedInstanceGroupInstalledPackagesOutput(args: GetManagedInstanceGroupInstalledPackagesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetManagedInstanceGroupInstalledPackagesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:OsManagementHub/getManagedInstanceGroupInstalledPackages:getManagedInstanceGroupInstalledPackages", {
        "compartmentId": args.compartmentId,
        "displayNameContains": args.displayNameContains,
        "displayNames": args.displayNames,
        "filters": args.filters,
        "managedInstanceGroupId": args.managedInstanceGroupId,
        "timeInstallDateEnd": args.timeInstallDateEnd,
        "timeInstallDateStart": args.timeInstallDateStart,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedInstanceGroupInstalledPackages.
 */
export interface GetManagedInstanceGroupInstalledPackagesOutputArgs {
    /**
     * The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * A filter to return resources that may partially match the given display name.
     */
    displayNameContains?: pulumi.Input<string>;
    /**
     * A filter to return resources that match the given display names.
     */
    displayNames?: pulumi.Input<pulumi.Input<string>[]>;
    filters?: pulumi.Input<pulumi.Input<inputs.OsManagementHub.GetManagedInstanceGroupInstalledPackagesFilterArgs>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
     */
    managedInstanceGroupId: pulumi.Input<string>;
    /**
     * A filter to return only packages that were installed on or before the date provided, in ISO 8601 format.  Example: 2017-07-14T02:40:00.000Z
     */
    timeInstallDateEnd?: pulumi.Input<string>;
    /**
     * The install date after which to list all packages, in ISO 8601 format  Example: 2017-07-14T02:40:00.000Z
     */
    timeInstallDateStart?: pulumi.Input<string>;
}
