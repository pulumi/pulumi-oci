// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Managed Instance Group Available Modules in Oracle Cloud Infrastructure Os Management Hub service.
 *
 * Lists available modules that for the specified managed instance group. Filter the list against a variety of
 * criteria including but not limited to its name.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedInstanceGroupAvailableModules = oci.OsManagementHub.getManagedInstanceGroupAvailableModules({
 *     managedInstanceGroupId: oci_os_management_hub_managed_instance_group.test_managed_instance_group.id,
 *     compartmentId: _var.compartment_id,
 *     name: _var.managed_instance_group_available_module_name,
 *     nameContains: _var.managed_instance_group_available_module_name_contains,
 * });
 * ```
 */
export function getManagedInstanceGroupAvailableModules(args: GetManagedInstanceGroupAvailableModulesArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedInstanceGroupAvailableModulesResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:OsManagementHub/getManagedInstanceGroupAvailableModules:getManagedInstanceGroupAvailableModules", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "managedInstanceGroupId": args.managedInstanceGroupId,
        "name": args.name,
        "nameContains": args.nameContains,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedInstanceGroupAvailableModules.
 */
export interface GetManagedInstanceGroupAvailableModulesArgs {
    /**
     * The OCID of the compartment that contains the resources to list.
     */
    compartmentId?: string;
    filters?: inputs.OsManagementHub.GetManagedInstanceGroupAvailableModulesFilter[];
    /**
     * The managed instance group OCID.
     */
    managedInstanceGroupId: string;
    /**
     * The resource name.
     */
    name?: string;
    /**
     * A filter to return resources that may partially match the name given.
     */
    nameContains?: string;
}

/**
 * A collection of values returned by getManagedInstanceGroupAvailableModules.
 */
export interface GetManagedInstanceGroupAvailableModulesResult {
    readonly compartmentId?: string;
    readonly filters?: outputs.OsManagementHub.GetManagedInstanceGroupAvailableModulesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of managed_instance_group_available_module_collection.
     */
    readonly managedInstanceGroupAvailableModuleCollections: outputs.OsManagementHub.GetManagedInstanceGroupAvailableModulesManagedInstanceGroupAvailableModuleCollection[];
    readonly managedInstanceGroupId: string;
    /**
     * The name of the module that is available to be enabled on the managed instance group.
     */
    readonly name?: string;
    readonly nameContains?: string;
}
/**
 * This data source provides the list of Managed Instance Group Available Modules in Oracle Cloud Infrastructure Os Management Hub service.
 *
 * Lists available modules that for the specified managed instance group. Filter the list against a variety of
 * criteria including but not limited to its name.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedInstanceGroupAvailableModules = oci.OsManagementHub.getManagedInstanceGroupAvailableModules({
 *     managedInstanceGroupId: oci_os_management_hub_managed_instance_group.test_managed_instance_group.id,
 *     compartmentId: _var.compartment_id,
 *     name: _var.managed_instance_group_available_module_name,
 *     nameContains: _var.managed_instance_group_available_module_name_contains,
 * });
 * ```
 */
export function getManagedInstanceGroupAvailableModulesOutput(args: GetManagedInstanceGroupAvailableModulesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetManagedInstanceGroupAvailableModulesResult> {
    return pulumi.output(args).apply((a: any) => getManagedInstanceGroupAvailableModules(a, opts))
}

/**
 * A collection of arguments for invoking getManagedInstanceGroupAvailableModules.
 */
export interface GetManagedInstanceGroupAvailableModulesOutputArgs {
    /**
     * The OCID of the compartment that contains the resources to list.
     */
    compartmentId?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.OsManagementHub.GetManagedInstanceGroupAvailableModulesFilterArgs>[]>;
    /**
     * The managed instance group OCID.
     */
    managedInstanceGroupId: pulumi.Input<string>;
    /**
     * The resource name.
     */
    name?: pulumi.Input<string>;
    /**
     * A filter to return resources that may partially match the name given.
     */
    nameContains?: pulumi.Input<string>;
}