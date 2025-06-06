// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * **Deprecated. This resource does not support create and update operations.**
 *
 * This resource provides the Discovery Jobs Result resource in Oracle Cloud Infrastructure Data Safe service.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDiscoveryJobsResult = new oci.datasafe.DiscoveryJobsResult("test_discovery_jobs_result", {});
 * ```
 *
 * ## Import
 *
 * DiscoveryJobsResults can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:DataSafe/discoveryJobsResult:DiscoveryJobsResult test_discovery_jobs_result "discoveryJobs/{discoveryJobId}/results/{resultKey}"
 * ```
 */
export class DiscoveryJobsResult extends pulumi.CustomResource {
    /**
     * Get an existing DiscoveryJobsResult resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: DiscoveryJobsResultState, opts?: pulumi.CustomResourceOptions): DiscoveryJobsResult {
        return new DiscoveryJobsResult(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DataSafe/discoveryJobsResult:DiscoveryJobsResult';

    /**
     * Returns true if the given object is an instance of DiscoveryJobsResult.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is DiscoveryJobsResult {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === DiscoveryJobsResult.__pulumiType;
    }

    /**
     * Unique keys identifying the columns that are application-level (non-dictionary) children of the sensitive column.
     */
    public /*out*/ readonly appDefinedChildColumnKeys!: pulumi.Output<string[]>;
    /**
     * The name of the application. An application is an entity that is identified by a schema and stores sensitive information for that schema. Its value will be same as schemaName, if no value is passed.
     */
    public /*out*/ readonly appName!: pulumi.Output<string>;
    /**
     * The name of the sensitive column.
     */
    public /*out*/ readonly columnName!: pulumi.Output<string>;
    /**
     * The data type of the sensitive column.
     */
    public /*out*/ readonly dataType!: pulumi.Output<string>;
    /**
     * Unique keys identifying the columns that are database-level (dictionary-defined) children of the sensitive column.
     */
    public /*out*/ readonly dbDefinedChildColumnKeys!: pulumi.Output<string[]>;
    /**
     * The OCID of the discovery job.
     *
     * @deprecated The 'oci_data_safe_discovery_jobs_result' resource has been deprecated. It is no longer supported.
     */
    public readonly discoveryJobId!: pulumi.Output<string>;
    /**
     * The type of the discovery result. It can be one of the following three types: NEW: A new sensitive column in the target database that is not in the sensitive data model. DELETED: A column that is present in the sensitive data model but has been deleted from the target database. MODIFIED: A column that is present in the target database as well as the sensitive data model but some of its attributes have been modified.
     *
     * @deprecated The 'oci_data_safe_discovery_jobs_result' resource has been deprecated. It is no longer supported.
     */
    public /*out*/ readonly discoveryType!: pulumi.Output<string>;
    /**
     * The estimated number of data values the column has in the associated database.
     */
    public /*out*/ readonly estimatedDataValueCount!: pulumi.Output<string>;
    /**
     * Indicates if the discovery result has been processed. You can update this attribute using the PatchDiscoveryJobResults operation to track whether the discovery result has already been processed and applied to the sensitive data model.
     */
    public /*out*/ readonly isResultApplied!: pulumi.Output<boolean>;
    /**
     * The unique key that identifies the discovery result.
     *
     * @deprecated The 'oci_data_safe_discovery_jobs_result' resource has been deprecated. It is no longer supported.
     */
    public /*out*/ readonly key!: pulumi.Output<string>;
    /**
     * The attributes of a sensitive column that have been modified in the target database. It's populated only in the case of MODIFIED discovery results and shows the new values of the modified attributes.
     */
    public /*out*/ readonly modifiedAttributes!: pulumi.Output<outputs.DataSafe.DiscoveryJobsResultModifiedAttribute[]>;
    /**
     * The database object that contains the sensitive column.
     */
    public /*out*/ readonly object!: pulumi.Output<string>;
    /**
     * The type of the database object that contains the sensitive column.
     */
    public /*out*/ readonly objectType!: pulumi.Output<string>;
    /**
     * Unique keys identifying the columns that are parents of the sensitive column. At present, it tracks a single parent only.
     */
    public /*out*/ readonly parentColumnKeys!: pulumi.Output<string[]>;
    /**
     * Specifies how to process the discovery result. It's set to NONE by default. Use the PatchDiscoveryJobResults operation to update this attribute. You can choose one of the following options: ACCEPT: To accept the discovery result and update the sensitive data model to reflect the changes. REJECT: To reject the discovery result so that it doesn't change the sensitive data model. INVALIDATE: To invalidate a newly discovered column. It adds the column to the sensitive data model but marks it as invalid. It helps track false positives and ensure that they aren't reported by future discovery jobs. After specifying the planned action, you can use the ApplyDiscoveryJobResults operation to automatically process the discovery results.
     */
    public /*out*/ readonly plannedAction!: pulumi.Output<string>;
    /**
     * The type of referential relationship the sensitive column has with its parent. NONE indicates that the sensitive column does not have a parent. DB_DEFINED indicates that the relationship is defined in the database dictionary. APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
     */
    public /*out*/ readonly relationType!: pulumi.Output<string>;
    /**
     * Original data values collected for the sensitive column from the associated database. Sample data helps review the column and ensure that it actually contains sensitive data. Note that sample data is retrieved by a data discovery job only if the isSampleDataCollectionEnabled attribute is set to true. At present, only one data value is collected per sensitive column.
     */
    public /*out*/ readonly sampleDataValues!: pulumi.Output<string[]>;
    /**
     * The database schema that contains the sensitive column.
     */
    public /*out*/ readonly schemaName!: pulumi.Output<string>;
    /**
     * The unique key that identifies the sensitive column represented by the discovery result.
     */
    public /*out*/ readonly sensitiveColumnkey!: pulumi.Output<string>;
    /**
     * The OCID of the sensitive type associated with the sensitive column.
     */
    public /*out*/ readonly sensitiveTypeId!: pulumi.Output<string>;

    /**
     * Create a DiscoveryJobsResult resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: DiscoveryJobsResultArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: DiscoveryJobsResultArgs | DiscoveryJobsResultState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as DiscoveryJobsResultState | undefined;
            resourceInputs["appDefinedChildColumnKeys"] = state ? state.appDefinedChildColumnKeys : undefined;
            resourceInputs["appName"] = state ? state.appName : undefined;
            resourceInputs["columnName"] = state ? state.columnName : undefined;
            resourceInputs["dataType"] = state ? state.dataType : undefined;
            resourceInputs["dbDefinedChildColumnKeys"] = state ? state.dbDefinedChildColumnKeys : undefined;
            resourceInputs["discoveryJobId"] = state ? state.discoveryJobId : undefined;
            resourceInputs["discoveryType"] = state ? state.discoveryType : undefined;
            resourceInputs["estimatedDataValueCount"] = state ? state.estimatedDataValueCount : undefined;
            resourceInputs["isResultApplied"] = state ? state.isResultApplied : undefined;
            resourceInputs["key"] = state ? state.key : undefined;
            resourceInputs["modifiedAttributes"] = state ? state.modifiedAttributes : undefined;
            resourceInputs["object"] = state ? state.object : undefined;
            resourceInputs["objectType"] = state ? state.objectType : undefined;
            resourceInputs["parentColumnKeys"] = state ? state.parentColumnKeys : undefined;
            resourceInputs["plannedAction"] = state ? state.plannedAction : undefined;
            resourceInputs["relationType"] = state ? state.relationType : undefined;
            resourceInputs["sampleDataValues"] = state ? state.sampleDataValues : undefined;
            resourceInputs["schemaName"] = state ? state.schemaName : undefined;
            resourceInputs["sensitiveColumnkey"] = state ? state.sensitiveColumnkey : undefined;
            resourceInputs["sensitiveTypeId"] = state ? state.sensitiveTypeId : undefined;
        } else {
            const args = argsOrState as DiscoveryJobsResultArgs | undefined;
            if ((!args || args.discoveryJobId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'discoveryJobId'");
            }
            resourceInputs["discoveryJobId"] = args ? args.discoveryJobId : undefined;
            resourceInputs["appDefinedChildColumnKeys"] = undefined /*out*/;
            resourceInputs["appName"] = undefined /*out*/;
            resourceInputs["columnName"] = undefined /*out*/;
            resourceInputs["dataType"] = undefined /*out*/;
            resourceInputs["dbDefinedChildColumnKeys"] = undefined /*out*/;
            resourceInputs["discoveryType"] = undefined /*out*/;
            resourceInputs["estimatedDataValueCount"] = undefined /*out*/;
            resourceInputs["isResultApplied"] = undefined /*out*/;
            resourceInputs["key"] = undefined /*out*/;
            resourceInputs["modifiedAttributes"] = undefined /*out*/;
            resourceInputs["object"] = undefined /*out*/;
            resourceInputs["objectType"] = undefined /*out*/;
            resourceInputs["parentColumnKeys"] = undefined /*out*/;
            resourceInputs["plannedAction"] = undefined /*out*/;
            resourceInputs["relationType"] = undefined /*out*/;
            resourceInputs["sampleDataValues"] = undefined /*out*/;
            resourceInputs["schemaName"] = undefined /*out*/;
            resourceInputs["sensitiveColumnkey"] = undefined /*out*/;
            resourceInputs["sensitiveTypeId"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(DiscoveryJobsResult.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering DiscoveryJobsResult resources.
 */
export interface DiscoveryJobsResultState {
    /**
     * Unique keys identifying the columns that are application-level (non-dictionary) children of the sensitive column.
     */
    appDefinedChildColumnKeys?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The name of the application. An application is an entity that is identified by a schema and stores sensitive information for that schema. Its value will be same as schemaName, if no value is passed.
     */
    appName?: pulumi.Input<string>;
    /**
     * The name of the sensitive column.
     */
    columnName?: pulumi.Input<string>;
    /**
     * The data type of the sensitive column.
     */
    dataType?: pulumi.Input<string>;
    /**
     * Unique keys identifying the columns that are database-level (dictionary-defined) children of the sensitive column.
     */
    dbDefinedChildColumnKeys?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The OCID of the discovery job.
     *
     * @deprecated The 'oci_data_safe_discovery_jobs_result' resource has been deprecated. It is no longer supported.
     */
    discoveryJobId?: pulumi.Input<string>;
    /**
     * The type of the discovery result. It can be one of the following three types: NEW: A new sensitive column in the target database that is not in the sensitive data model. DELETED: A column that is present in the sensitive data model but has been deleted from the target database. MODIFIED: A column that is present in the target database as well as the sensitive data model but some of its attributes have been modified.
     *
     * @deprecated The 'oci_data_safe_discovery_jobs_result' resource has been deprecated. It is no longer supported.
     */
    discoveryType?: pulumi.Input<string>;
    /**
     * The estimated number of data values the column has in the associated database.
     */
    estimatedDataValueCount?: pulumi.Input<string>;
    /**
     * Indicates if the discovery result has been processed. You can update this attribute using the PatchDiscoveryJobResults operation to track whether the discovery result has already been processed and applied to the sensitive data model.
     */
    isResultApplied?: pulumi.Input<boolean>;
    /**
     * The unique key that identifies the discovery result.
     *
     * @deprecated The 'oci_data_safe_discovery_jobs_result' resource has been deprecated. It is no longer supported.
     */
    key?: pulumi.Input<string>;
    /**
     * The attributes of a sensitive column that have been modified in the target database. It's populated only in the case of MODIFIED discovery results and shows the new values of the modified attributes.
     */
    modifiedAttributes?: pulumi.Input<pulumi.Input<inputs.DataSafe.DiscoveryJobsResultModifiedAttribute>[]>;
    /**
     * The database object that contains the sensitive column.
     */
    object?: pulumi.Input<string>;
    /**
     * The type of the database object that contains the sensitive column.
     */
    objectType?: pulumi.Input<string>;
    /**
     * Unique keys identifying the columns that are parents of the sensitive column. At present, it tracks a single parent only.
     */
    parentColumnKeys?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Specifies how to process the discovery result. It's set to NONE by default. Use the PatchDiscoveryJobResults operation to update this attribute. You can choose one of the following options: ACCEPT: To accept the discovery result and update the sensitive data model to reflect the changes. REJECT: To reject the discovery result so that it doesn't change the sensitive data model. INVALIDATE: To invalidate a newly discovered column. It adds the column to the sensitive data model but marks it as invalid. It helps track false positives and ensure that they aren't reported by future discovery jobs. After specifying the planned action, you can use the ApplyDiscoveryJobResults operation to automatically process the discovery results.
     */
    plannedAction?: pulumi.Input<string>;
    /**
     * The type of referential relationship the sensitive column has with its parent. NONE indicates that the sensitive column does not have a parent. DB_DEFINED indicates that the relationship is defined in the database dictionary. APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
     */
    relationType?: pulumi.Input<string>;
    /**
     * Original data values collected for the sensitive column from the associated database. Sample data helps review the column and ensure that it actually contains sensitive data. Note that sample data is retrieved by a data discovery job only if the isSampleDataCollectionEnabled attribute is set to true. At present, only one data value is collected per sensitive column.
     */
    sampleDataValues?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The database schema that contains the sensitive column.
     */
    schemaName?: pulumi.Input<string>;
    /**
     * The unique key that identifies the sensitive column represented by the discovery result.
     */
    sensitiveColumnkey?: pulumi.Input<string>;
    /**
     * The OCID of the sensitive type associated with the sensitive column.
     */
    sensitiveTypeId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a DiscoveryJobsResult resource.
 */
export interface DiscoveryJobsResultArgs {
    /**
     * The OCID of the discovery job.
     *
     * @deprecated The 'oci_data_safe_discovery_jobs_result' resource has been deprecated. It is no longer supported.
     */
    discoveryJobId: pulumi.Input<string>;
}
