// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Compliance Records in Oracle Cloud Infrastructure Fleet Apps Management service.
 *
 * Gets a list of complianceDetails.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testComplianceRecords = oci.FleetAppsManagement.getComplianceRecords({
 *     compartmentId: compartmentId,
 *     compartmentIdInSubtree: complianceRecordCompartmentIdInSubtree,
 *     complianceState: complianceRecordComplianceState,
 *     entityId: testEntity.id,
 *     productName: complianceRecordProductName,
 *     productStack: complianceRecordProductStack,
 *     resourceId: testResource.id,
 *     targetName: testTarget.name,
 * });
 * ```
 */
export function getComplianceRecords(args: GetComplianceRecordsArgs, opts?: pulumi.InvokeOptions): Promise<GetComplianceRecordsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:FleetAppsManagement/getComplianceRecords:getComplianceRecords", {
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "complianceState": args.complianceState,
        "entityId": args.entityId,
        "filters": args.filters,
        "productName": args.productName,
        "productStack": args.productStack,
        "resourceId": args.resourceId,
        "targetName": args.targetName,
    }, opts);
}

/**
 * A collection of arguments for invoking getComplianceRecords.
 */
export interface GetComplianceRecordsArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * If set to true, resources will be returned for not only the provided compartment, but all compartments which descend from it. Which resources are returned and their field contents depends on the value of accessLevel.
     */
    compartmentIdInSubtree?: boolean;
    /**
     * Target Compliance State.
     */
    complianceState?: string;
    /**
     * Entity identifier.Ex:FleetId
     */
    entityId?: string;
    filters?: inputs.FleetAppsManagement.GetComplianceRecordsFilter[];
    /**
     * Product Name.
     */
    productName?: string;
    /**
     * ProductStack name.
     */
    productStack?: string;
    /**
     * Resource identifier.
     */
    resourceId?: string;
    /**
     * Unique target name
     */
    targetName?: string;
}

/**
 * A collection of values returned by getComplianceRecords.
 */
export interface GetComplianceRecordsResult {
    /**
     * Compartment OCID of the resource.
     */
    readonly compartmentId: string;
    readonly compartmentIdInSubtree?: boolean;
    /**
     * The list of compliance_record_collection.
     */
    readonly complianceRecordCollections: outputs.FleetAppsManagement.GetComplianceRecordsComplianceRecordCollection[];
    /**
     * Last known compliance state of target.
     */
    readonly complianceState?: string;
    /**
     * The OCID of the entity for which the compliance is calculated.Ex.FleetId
     */
    readonly entityId?: string;
    readonly filters?: outputs.FleetAppsManagement.GetComplianceRecordsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Product Name.
     */
    readonly productName?: string;
    /**
     * Product Stack.
     */
    readonly productStack?: string;
    /**
     * The OCID to identify the resource.
     */
    readonly resourceId?: string;
    /**
     * Target Name.
     */
    readonly targetName?: string;
}
/**
 * This data source provides the list of Compliance Records in Oracle Cloud Infrastructure Fleet Apps Management service.
 *
 * Gets a list of complianceDetails.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testComplianceRecords = oci.FleetAppsManagement.getComplianceRecords({
 *     compartmentId: compartmentId,
 *     compartmentIdInSubtree: complianceRecordCompartmentIdInSubtree,
 *     complianceState: complianceRecordComplianceState,
 *     entityId: testEntity.id,
 *     productName: complianceRecordProductName,
 *     productStack: complianceRecordProductStack,
 *     resourceId: testResource.id,
 *     targetName: testTarget.name,
 * });
 * ```
 */
export function getComplianceRecordsOutput(args: GetComplianceRecordsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetComplianceRecordsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:FleetAppsManagement/getComplianceRecords:getComplianceRecords", {
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "complianceState": args.complianceState,
        "entityId": args.entityId,
        "filters": args.filters,
        "productName": args.productName,
        "productStack": args.productStack,
        "resourceId": args.resourceId,
        "targetName": args.targetName,
    }, opts);
}

/**
 * A collection of arguments for invoking getComplianceRecords.
 */
export interface GetComplianceRecordsOutputArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * If set to true, resources will be returned for not only the provided compartment, but all compartments which descend from it. Which resources are returned and their field contents depends on the value of accessLevel.
     */
    compartmentIdInSubtree?: pulumi.Input<boolean>;
    /**
     * Target Compliance State.
     */
    complianceState?: pulumi.Input<string>;
    /**
     * Entity identifier.Ex:FleetId
     */
    entityId?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.FleetAppsManagement.GetComplianceRecordsFilterArgs>[]>;
    /**
     * Product Name.
     */
    productName?: pulumi.Input<string>;
    /**
     * ProductStack name.
     */
    productStack?: pulumi.Input<string>;
    /**
     * Resource identifier.
     */
    resourceId?: pulumi.Input<string>;
    /**
     * Unique target name
     */
    targetName?: pulumi.Input<string>;
}
