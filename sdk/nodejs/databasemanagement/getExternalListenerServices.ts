// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of External Listener Services in Oracle Cloud Infrastructure Database Management service.
 *
 * Lists the database services registered with the specified external listener
 * for the specified Managed Database.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExternalListenerServices = oci.DatabaseManagement.getExternalListenerServices({
 *     externalListenerId: oci_database_management_external_listener.test_external_listener.id,
 *     managedDatabaseId: oci_database_management_managed_database.test_managed_database.id,
 * });
 * ```
 */
export function getExternalListenerServices(args: GetExternalListenerServicesArgs, opts?: pulumi.InvokeOptions): Promise<GetExternalListenerServicesResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DatabaseManagement/getExternalListenerServices:getExternalListenerServices", {
        "externalListenerId": args.externalListenerId,
        "filters": args.filters,
        "managedDatabaseId": args.managedDatabaseId,
    }, opts);
}

/**
 * A collection of arguments for invoking getExternalListenerServices.
 */
export interface GetExternalListenerServicesArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external listener.
     */
    externalListenerId: string;
    filters?: inputs.DatabaseManagement.GetExternalListenerServicesFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: string;
}

/**
 * A collection of values returned by getExternalListenerServices.
 */
export interface GetExternalListenerServicesResult {
    readonly externalListenerId: string;
    /**
     * The list of external_listener_service_collection.
     */
    readonly externalListenerServiceCollections: outputs.DatabaseManagement.GetExternalListenerServicesExternalListenerServiceCollection[];
    readonly filters?: outputs.DatabaseManagement.GetExternalListenerServicesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    readonly managedDatabaseId: string;
}
/**
 * This data source provides the list of External Listener Services in Oracle Cloud Infrastructure Database Management service.
 *
 * Lists the database services registered with the specified external listener
 * for the specified Managed Database.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExternalListenerServices = oci.DatabaseManagement.getExternalListenerServices({
 *     externalListenerId: oci_database_management_external_listener.test_external_listener.id,
 *     managedDatabaseId: oci_database_management_managed_database.test_managed_database.id,
 * });
 * ```
 */
export function getExternalListenerServicesOutput(args: GetExternalListenerServicesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetExternalListenerServicesResult> {
    return pulumi.output(args).apply((a: any) => getExternalListenerServices(a, opts))
}

/**
 * A collection of arguments for invoking getExternalListenerServices.
 */
export interface GetExternalListenerServicesOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external listener.
     */
    externalListenerId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.DatabaseManagement.GetExternalListenerServicesFilterArgs>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: pulumi.Input<string>;
}