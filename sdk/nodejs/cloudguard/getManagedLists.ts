// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Managed Lists in Oracle Cloud Infrastructure Cloud Guard service.
 *
 * Returns a list of all ManagedList resources in a compartment, identified by compartmentId.
 * The ListManagedLists operation returns only the managed lists in `compartmentId` passed.
 * The list does not include any subcompartments of the compartmentId passed.
 *
 * The parameter `accessLevel` specifies whether to return ManagedLists in only
 * those compartments for which the requestor has INSPECT permissions on at least one resource directly
 * or indirectly (ACCESSIBLE) (the resource can be in a subcompartment) or to return Not Authorized if
 * Principal doesn't have access to even one of the child compartments. This is valid only when
 * `compartmentIdInSubtree` is set to `true`.
 *
 * The parameter `compartmentIdInSubtree` applies when you perform ListManagedLists on the
 * `compartmentId` passed and when it is set to true, the entire hierarchy of compartments can be returned.
 * To get a full list of all compartments and subcompartments in the tenancy (root compartment),
 * set the parameter `compartmentIdInSubtree` to true and `accessLevel` to ACCESSIBLE.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedLists = oci.CloudGuard.getManagedLists({
 *     compartmentId: compartmentId,
 *     accessLevel: managedListAccessLevel,
 *     compartmentIdInSubtree: managedListCompartmentIdInSubtree,
 *     displayName: managedListDisplayName,
 *     listType: managedListListType,
 *     resourceMetadataOnly: managedListResourceMetadataOnly,
 *     state: managedListState,
 * });
 * ```
 */
export function getManagedLists(args: GetManagedListsArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedListsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:CloudGuard/getManagedLists:getManagedLists", {
        "accessLevel": args.accessLevel,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "displayName": args.displayName,
        "filters": args.filters,
        "listType": args.listType,
        "resourceMetadataOnly": args.resourceMetadataOnly,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedLists.
 */
export interface GetManagedListsArgs {
    /**
     * Valid values are `RESTRICTED` and `ACCESSIBLE`. Default is `RESTRICTED`. Setting this to `ACCESSIBLE` returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to `RESTRICTED` permissions are checked and no partial results are displayed.
     */
    accessLevel?: string;
    /**
     * The OCID of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the setting of `accessLevel`.
     */
    compartmentIdInSubtree?: boolean;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: string;
    filters?: inputs.CloudGuard.GetManagedListsFilter[];
    /**
     * The type of managed list.
     */
    listType?: string;
    /**
     * Default is false. When set to true, the list of all Oracle-managed resources metadata supported by Cloud Guard is returned.
     */
    resourceMetadataOnly?: boolean;
    /**
     * The field lifecycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
     */
    state?: string;
}

/**
 * A collection of values returned by getManagedLists.
 */
export interface GetManagedListsResult {
    readonly accessLevel?: string;
    /**
     * Compartment OCID where the resource is created
     */
    readonly compartmentId: string;
    readonly compartmentIdInSubtree?: boolean;
    /**
     * Managed list display name
     */
    readonly displayName?: string;
    readonly filters?: outputs.CloudGuard.GetManagedListsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Type of information contained in the managed list
     */
    readonly listType?: string;
    /**
     * The list of managed_list_collection.
     */
    readonly managedListCollections: outputs.CloudGuard.GetManagedListsManagedListCollection[];
    readonly resourceMetadataOnly?: boolean;
    /**
     * The current lifecycle state of the resource
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Managed Lists in Oracle Cloud Infrastructure Cloud Guard service.
 *
 * Returns a list of all ManagedList resources in a compartment, identified by compartmentId.
 * The ListManagedLists operation returns only the managed lists in `compartmentId` passed.
 * The list does not include any subcompartments of the compartmentId passed.
 *
 * The parameter `accessLevel` specifies whether to return ManagedLists in only
 * those compartments for which the requestor has INSPECT permissions on at least one resource directly
 * or indirectly (ACCESSIBLE) (the resource can be in a subcompartment) or to return Not Authorized if
 * Principal doesn't have access to even one of the child compartments. This is valid only when
 * `compartmentIdInSubtree` is set to `true`.
 *
 * The parameter `compartmentIdInSubtree` applies when you perform ListManagedLists on the
 * `compartmentId` passed and when it is set to true, the entire hierarchy of compartments can be returned.
 * To get a full list of all compartments and subcompartments in the tenancy (root compartment),
 * set the parameter `compartmentIdInSubtree` to true and `accessLevel` to ACCESSIBLE.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedLists = oci.CloudGuard.getManagedLists({
 *     compartmentId: compartmentId,
 *     accessLevel: managedListAccessLevel,
 *     compartmentIdInSubtree: managedListCompartmentIdInSubtree,
 *     displayName: managedListDisplayName,
 *     listType: managedListListType,
 *     resourceMetadataOnly: managedListResourceMetadataOnly,
 *     state: managedListState,
 * });
 * ```
 */
export function getManagedListsOutput(args: GetManagedListsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetManagedListsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:CloudGuard/getManagedLists:getManagedLists", {
        "accessLevel": args.accessLevel,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "displayName": args.displayName,
        "filters": args.filters,
        "listType": args.listType,
        "resourceMetadataOnly": args.resourceMetadataOnly,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedLists.
 */
export interface GetManagedListsOutputArgs {
    /**
     * Valid values are `RESTRICTED` and `ACCESSIBLE`. Default is `RESTRICTED`. Setting this to `ACCESSIBLE` returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to `RESTRICTED` permissions are checked and no partial results are displayed.
     */
    accessLevel?: pulumi.Input<string>;
    /**
     * The OCID of the compartment in which to list resources.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the setting of `accessLevel`.
     */
    compartmentIdInSubtree?: pulumi.Input<boolean>;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.CloudGuard.GetManagedListsFilterArgs>[]>;
    /**
     * The type of managed list.
     */
    listType?: pulumi.Input<string>;
    /**
     * Default is false. When set to true, the list of all Oracle-managed resources metadata supported by Cloud Guard is returned.
     */
    resourceMetadataOnly?: pulumi.Input<boolean>;
    /**
     * The field lifecycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
     */
    state?: pulumi.Input<string>;
}
