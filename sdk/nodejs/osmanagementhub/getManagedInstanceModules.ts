// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Managed Instance Modules in Oracle Cloud Infrastructure Os Management Hub service.
 *
 * Retrieves a list of modules, along with streams of the modules, from a managed instance. Filters may be applied to select a subset of modules based on the filter criteria.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedInstanceModules = oci.OsManagementHub.getManagedInstanceModules({
 *     managedInstanceId: testManagedInstance.id,
 *     compartmentId: compartmentId,
 *     name: managedInstanceModuleName,
 *     nameContains: managedInstanceModuleNameContains,
 * });
 * ```
 */
export function getManagedInstanceModules(args: GetManagedInstanceModulesArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedInstanceModulesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:OsManagementHub/getManagedInstanceModules:getManagedInstanceModules", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "managedInstanceId": args.managedInstanceId,
        "name": args.name,
        "nameContains": args.nameContains,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedInstanceModules.
 */
export interface GetManagedInstanceModulesArgs {
    /**
     * The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
     */
    compartmentId?: string;
    filters?: inputs.OsManagementHub.GetManagedInstanceModulesFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
     */
    managedInstanceId: string;
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
 * A collection of values returned by getManagedInstanceModules.
 */
export interface GetManagedInstanceModulesResult {
    readonly compartmentId?: string;
    readonly filters?: outputs.OsManagementHub.GetManagedInstanceModulesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly managedInstanceId: string;
    /**
     * The list of managed_instance_module_collection.
     */
    readonly managedInstanceModuleCollections: outputs.OsManagementHub.GetManagedInstanceModulesManagedInstanceModuleCollection[];
    /**
     * The module name.
     */
    readonly name?: string;
    readonly nameContains?: string;
}
/**
 * This data source provides the list of Managed Instance Modules in Oracle Cloud Infrastructure Os Management Hub service.
 *
 * Retrieves a list of modules, along with streams of the modules, from a managed instance. Filters may be applied to select a subset of modules based on the filter criteria.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedInstanceModules = oci.OsManagementHub.getManagedInstanceModules({
 *     managedInstanceId: testManagedInstance.id,
 *     compartmentId: compartmentId,
 *     name: managedInstanceModuleName,
 *     nameContains: managedInstanceModuleNameContains,
 * });
 * ```
 */
export function getManagedInstanceModulesOutput(args: GetManagedInstanceModulesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetManagedInstanceModulesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:OsManagementHub/getManagedInstanceModules:getManagedInstanceModules", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "managedInstanceId": args.managedInstanceId,
        "name": args.name,
        "nameContains": args.nameContains,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedInstanceModules.
 */
export interface GetManagedInstanceModulesOutputArgs {
    /**
     * The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
     */
    compartmentId?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.OsManagementHub.GetManagedInstanceModulesFilterArgs>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
     */
    managedInstanceId: pulumi.Input<string>;
    /**
     * The resource name.
     */
    name?: pulumi.Input<string>;
    /**
     * A filter to return resources that may partially match the name given.
     */
    nameContains?: pulumi.Input<string>;
}
