// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Sensitive Column Analytics in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets consolidated sensitive columns analytics data based on the specified query parameters.
 *
 * When you perform the ListSensitiveColumnAnalytics operation, if the parameter compartmentIdInSubtree is set to "true," and if the
 * parameter accessLevel is set to ACCESSIBLE, then the operation returns compartments in which the requestor has INSPECT
 * permissions on at least one resource, directly or indirectly (in subcompartments). If the operation is performed at the
 * root compartment and the requestor does not have access to at least one subcompartment of the compartment specified by
 * compartmentId, then "Not Authorized" is returned.
 *
 * To use ListSensitiveColumnAnalytics to get a full list of all compartments and subcompartments in the tenancy from the root compartment,
 * set the parameter compartmentIdInSubtree to true and accessLevel to ACCESSIBLE.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSensitiveColumnAnalytics = oci.DataSafe.getSensitiveColumnAnalytics({
 *     compartmentId: compartmentId,
 *     accessLevel: sensitiveColumnAnalyticAccessLevel,
 *     columnNames: sensitiveColumnAnalyticColumnName,
 *     compartmentIdInSubtree: sensitiveColumnAnalyticCompartmentIdInSubtree,
 *     groupBies: sensitiveColumnAnalyticGroupBy,
 *     objects: sensitiveColumnAnalyticObject,
 *     schemaNames: sensitiveColumnAnalyticSchemaName,
 *     sensitiveDataModelId: testSensitiveDataModel.id,
 *     sensitiveTypeGroupId: testSensitiveTypeGroup.id,
 *     sensitiveTypeIds: testSensitiveType.id,
 *     targetId: testTarget.id,
 * });
 * ```
 */
export function getSensitiveColumnAnalytics(args: GetSensitiveColumnAnalyticsArgs, opts?: pulumi.InvokeOptions): Promise<GetSensitiveColumnAnalyticsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataSafe/getSensitiveColumnAnalytics:getSensitiveColumnAnalytics", {
        "accessLevel": args.accessLevel,
        "columnNames": args.columnNames,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "filters": args.filters,
        "groupBies": args.groupBies,
        "objects": args.objects,
        "schemaNames": args.schemaNames,
        "sensitiveDataModelId": args.sensitiveDataModelId,
        "sensitiveTypeGroupId": args.sensitiveTypeGroupId,
        "sensitiveTypeIds": args.sensitiveTypeIds,
        "targetId": args.targetId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSensitiveColumnAnalytics.
 */
export interface GetSensitiveColumnAnalyticsArgs {
    /**
     * Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     */
    accessLevel?: string;
    /**
     * A filter to return only a specific column based on column name.
     */
    columnNames?: string[];
    /**
     * A filter to return only resources that match the specified compartment OCID.
     */
    compartmentId: string;
    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
     */
    compartmentIdInSubtree?: boolean;
    filters?: inputs.DataSafe.GetSensitiveColumnAnalyticsFilter[];
    /**
     * The group by parameter to summarize the sensitive columns.
     */
    groupBies?: string[];
    /**
     * A filter to return only items related to a specific object name.
     */
    objects?: string[];
    /**
     * A filter to return only items related to specific schema name.
     */
    schemaNames?: string[];
    /**
     * A filter to return only the resources that match the specified sensitive data model OCID.
     */
    sensitiveDataModelId?: string;
    /**
     * An optional filter to return only resources that match the specified OCID of the sensitive type group resource.
     */
    sensitiveTypeGroupId?: string;
    /**
     * A filter to return only the sensitive columns that are associated with one of the sensitive types identified by the specified OCIDs.
     */
    sensitiveTypeIds?: string[];
    /**
     * A filter to return only items related to a specific target OCID.
     */
    targetId?: string;
}

/**
 * A collection of values returned by getSensitiveColumnAnalytics.
 */
export interface GetSensitiveColumnAnalyticsResult {
    readonly accessLevel?: string;
    /**
     * The name of the sensitive column.
     */
    readonly columnNames?: string[];
    readonly compartmentId: string;
    readonly compartmentIdInSubtree?: boolean;
    readonly filters?: outputs.DataSafe.GetSensitiveColumnAnalyticsFilter[];
    readonly groupBies?: string[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The database object that contains the sensitive column.
     */
    readonly objects?: string[];
    /**
     * The database schema that contains the sensitive column.
     */
    readonly schemaNames?: string[];
    /**
     * The list of sensitive_column_analytics_collection.
     */
    readonly sensitiveColumnAnalyticsCollections: outputs.DataSafe.GetSensitiveColumnAnalyticsSensitiveColumnAnalyticsCollection[];
    /**
     * The OCID of the sensitive data model which contains the sensitive column.
     */
    readonly sensitiveDataModelId?: string;
    readonly sensitiveTypeGroupId?: string;
    /**
     * The OCID of the sensitive type associated with the sensitive column.
     */
    readonly sensitiveTypeIds?: string[];
    /**
     * The OCID of the target database associated with the sensitive column.
     */
    readonly targetId?: string;
}
/**
 * This data source provides the list of Sensitive Column Analytics in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets consolidated sensitive columns analytics data based on the specified query parameters.
 *
 * When you perform the ListSensitiveColumnAnalytics operation, if the parameter compartmentIdInSubtree is set to "true," and if the
 * parameter accessLevel is set to ACCESSIBLE, then the operation returns compartments in which the requestor has INSPECT
 * permissions on at least one resource, directly or indirectly (in subcompartments). If the operation is performed at the
 * root compartment and the requestor does not have access to at least one subcompartment of the compartment specified by
 * compartmentId, then "Not Authorized" is returned.
 *
 * To use ListSensitiveColumnAnalytics to get a full list of all compartments and subcompartments in the tenancy from the root compartment,
 * set the parameter compartmentIdInSubtree to true and accessLevel to ACCESSIBLE.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSensitiveColumnAnalytics = oci.DataSafe.getSensitiveColumnAnalytics({
 *     compartmentId: compartmentId,
 *     accessLevel: sensitiveColumnAnalyticAccessLevel,
 *     columnNames: sensitiveColumnAnalyticColumnName,
 *     compartmentIdInSubtree: sensitiveColumnAnalyticCompartmentIdInSubtree,
 *     groupBies: sensitiveColumnAnalyticGroupBy,
 *     objects: sensitiveColumnAnalyticObject,
 *     schemaNames: sensitiveColumnAnalyticSchemaName,
 *     sensitiveDataModelId: testSensitiveDataModel.id,
 *     sensitiveTypeGroupId: testSensitiveTypeGroup.id,
 *     sensitiveTypeIds: testSensitiveType.id,
 *     targetId: testTarget.id,
 * });
 * ```
 */
export function getSensitiveColumnAnalyticsOutput(args: GetSensitiveColumnAnalyticsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetSensitiveColumnAnalyticsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataSafe/getSensitiveColumnAnalytics:getSensitiveColumnAnalytics", {
        "accessLevel": args.accessLevel,
        "columnNames": args.columnNames,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "filters": args.filters,
        "groupBies": args.groupBies,
        "objects": args.objects,
        "schemaNames": args.schemaNames,
        "sensitiveDataModelId": args.sensitiveDataModelId,
        "sensitiveTypeGroupId": args.sensitiveTypeGroupId,
        "sensitiveTypeIds": args.sensitiveTypeIds,
        "targetId": args.targetId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSensitiveColumnAnalytics.
 */
export interface GetSensitiveColumnAnalyticsOutputArgs {
    /**
     * Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     */
    accessLevel?: pulumi.Input<string>;
    /**
     * A filter to return only a specific column based on column name.
     */
    columnNames?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return only resources that match the specified compartment OCID.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
     */
    compartmentIdInSubtree?: pulumi.Input<boolean>;
    filters?: pulumi.Input<pulumi.Input<inputs.DataSafe.GetSensitiveColumnAnalyticsFilterArgs>[]>;
    /**
     * The group by parameter to summarize the sensitive columns.
     */
    groupBies?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return only items related to a specific object name.
     */
    objects?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return only items related to specific schema name.
     */
    schemaNames?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return only the resources that match the specified sensitive data model OCID.
     */
    sensitiveDataModelId?: pulumi.Input<string>;
    /**
     * An optional filter to return only resources that match the specified OCID of the sensitive type group resource.
     */
    sensitiveTypeGroupId?: pulumi.Input<string>;
    /**
     * A filter to return only the sensitive columns that are associated with one of the sensitive types identified by the specified OCIDs.
     */
    sensitiveTypeIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return only items related to a specific target OCID.
     */
    targetId?: pulumi.Input<string>;
}
