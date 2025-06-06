// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Managed Instance Group Available Packages in Oracle Cloud Infrastructure Os Management Hub service.
 *
 * Lists available packages on the specified managed instances group. Filter the list against a variety
 * of criteria including but not limited to the package name.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedInstanceGroupAvailablePackages = oci.OsManagementHub.getManagedInstanceGroupAvailablePackages({
 *     managedInstanceGroupId: testManagedInstanceGroup.id,
 *     compartmentId: compartmentId,
 *     displayNames: managedInstanceGroupAvailablePackageDisplayName,
 *     displayNameContains: managedInstanceGroupAvailablePackageDisplayNameContains,
 *     isLatest: managedInstanceGroupAvailablePackageIsLatest,
 * });
 * ```
 */
export function getManagedInstanceGroupAvailablePackages(args: GetManagedInstanceGroupAvailablePackagesArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedInstanceGroupAvailablePackagesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:OsManagementHub/getManagedInstanceGroupAvailablePackages:getManagedInstanceGroupAvailablePackages", {
        "compartmentId": args.compartmentId,
        "displayNameContains": args.displayNameContains,
        "displayNames": args.displayNames,
        "filters": args.filters,
        "isLatest": args.isLatest,
        "managedInstanceGroupId": args.managedInstanceGroupId,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedInstanceGroupAvailablePackages.
 */
export interface GetManagedInstanceGroupAvailablePackagesArgs {
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
    filters?: inputs.OsManagementHub.GetManagedInstanceGroupAvailablePackagesFilter[];
    /**
     * Indicates whether to list only the latest versions of packages, module streams, and stream profiles.
     */
    isLatest?: boolean;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
     */
    managedInstanceGroupId: string;
}

/**
 * A collection of values returned by getManagedInstanceGroupAvailablePackages.
 */
export interface GetManagedInstanceGroupAvailablePackagesResult {
    readonly compartmentId?: string;
    readonly displayNameContains?: string;
    /**
     * Software source name.
     */
    readonly displayNames?: string[];
    readonly filters?: outputs.OsManagementHub.GetManagedInstanceGroupAvailablePackagesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Indicates whether this is the latest package version.
     */
    readonly isLatest?: boolean;
    /**
     * The list of managed_instance_group_available_package_collection.
     */
    readonly managedInstanceGroupAvailablePackageCollections: outputs.OsManagementHub.GetManagedInstanceGroupAvailablePackagesManagedInstanceGroupAvailablePackageCollection[];
    readonly managedInstanceGroupId: string;
}
/**
 * This data source provides the list of Managed Instance Group Available Packages in Oracle Cloud Infrastructure Os Management Hub service.
 *
 * Lists available packages on the specified managed instances group. Filter the list against a variety
 * of criteria including but not limited to the package name.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedInstanceGroupAvailablePackages = oci.OsManagementHub.getManagedInstanceGroupAvailablePackages({
 *     managedInstanceGroupId: testManagedInstanceGroup.id,
 *     compartmentId: compartmentId,
 *     displayNames: managedInstanceGroupAvailablePackageDisplayName,
 *     displayNameContains: managedInstanceGroupAvailablePackageDisplayNameContains,
 *     isLatest: managedInstanceGroupAvailablePackageIsLatest,
 * });
 * ```
 */
export function getManagedInstanceGroupAvailablePackagesOutput(args: GetManagedInstanceGroupAvailablePackagesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetManagedInstanceGroupAvailablePackagesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:OsManagementHub/getManagedInstanceGroupAvailablePackages:getManagedInstanceGroupAvailablePackages", {
        "compartmentId": args.compartmentId,
        "displayNameContains": args.displayNameContains,
        "displayNames": args.displayNames,
        "filters": args.filters,
        "isLatest": args.isLatest,
        "managedInstanceGroupId": args.managedInstanceGroupId,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedInstanceGroupAvailablePackages.
 */
export interface GetManagedInstanceGroupAvailablePackagesOutputArgs {
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
    filters?: pulumi.Input<pulumi.Input<inputs.OsManagementHub.GetManagedInstanceGroupAvailablePackagesFilterArgs>[]>;
    /**
     * Indicates whether to list only the latest versions of packages, module streams, and stream profiles.
     */
    isLatest?: pulumi.Input<boolean>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
     */
    managedInstanceGroupId: pulumi.Input<string>;
}
