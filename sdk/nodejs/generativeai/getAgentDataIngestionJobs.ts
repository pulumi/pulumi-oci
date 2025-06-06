// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Data Ingestion Jobs in Oracle Cloud Infrastructure Generative Ai Agent service.
 *
 * **ListDataIngestionJobs**
 *
 * Gets a list of data ingestion jobs.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDataIngestionJobs = oci.GenerativeAi.getAgentDataIngestionJobs({
 *     compartmentId: compartmentId,
 *     dataSourceId: testDataSource.id,
 *     displayName: dataIngestionJobDisplayName,
 *     state: dataIngestionJobState,
 * });
 * ```
 */
export function getAgentDataIngestionJobs(args?: GetAgentDataIngestionJobsArgs, opts?: pulumi.InvokeOptions): Promise<GetAgentDataIngestionJobsResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:GenerativeAi/getAgentDataIngestionJobs:getAgentDataIngestionJobs", {
        "compartmentId": args.compartmentId,
        "dataSourceId": args.dataSourceId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getAgentDataIngestionJobs.
 */
export interface GetAgentDataIngestionJobsArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     */
    compartmentId?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the data source.
     */
    dataSourceId?: string;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: string;
    filters?: inputs.GenerativeAi.GetAgentDataIngestionJobsFilter[];
    /**
     * A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
     */
    state?: string;
}

/**
 * A collection of values returned by getAgentDataIngestionJobs.
 */
export interface GetAgentDataIngestionJobsResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId?: string;
    /**
     * The list of data_ingestion_job_collection.
     */
    readonly dataIngestionJobCollections: outputs.GenerativeAi.GetAgentDataIngestionJobsDataIngestionJobCollection[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the parent DataSource.
     */
    readonly dataSourceId?: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable.
     */
    readonly displayName?: string;
    readonly filters?: outputs.GenerativeAi.GetAgentDataIngestionJobsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current state of the data ingestion job.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Data Ingestion Jobs in Oracle Cloud Infrastructure Generative Ai Agent service.
 *
 * **ListDataIngestionJobs**
 *
 * Gets a list of data ingestion jobs.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDataIngestionJobs = oci.GenerativeAi.getAgentDataIngestionJobs({
 *     compartmentId: compartmentId,
 *     dataSourceId: testDataSource.id,
 *     displayName: dataIngestionJobDisplayName,
 *     state: dataIngestionJobState,
 * });
 * ```
 */
export function getAgentDataIngestionJobsOutput(args?: GetAgentDataIngestionJobsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetAgentDataIngestionJobsResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:GenerativeAi/getAgentDataIngestionJobs:getAgentDataIngestionJobs", {
        "compartmentId": args.compartmentId,
        "dataSourceId": args.dataSourceId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getAgentDataIngestionJobs.
 */
export interface GetAgentDataIngestionJobsOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the data source.
     */
    dataSourceId?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.GenerativeAi.GetAgentDataIngestionJobsFilterArgs>[]>;
    /**
     * A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
     */
    state?: pulumi.Input<string>;
}
