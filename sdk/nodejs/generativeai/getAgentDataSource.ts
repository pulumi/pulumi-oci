// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Data Source resource in Oracle Cloud Infrastructure Generative Ai Agent service.
 *
 * **GetDataSource**
 *
 * Gets information about a data source.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDataSource = oci.GenerativeAi.getAgentDataSource({
 *     dataSourceId: testDataSourceOciGenerativeAiAgentDataSource.id,
 * });
 * ```
 */
export function getAgentDataSource(args: GetAgentDataSourceArgs, opts?: pulumi.InvokeOptions): Promise<GetAgentDataSourceResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:GenerativeAi/getAgentDataSource:getAgentDataSource", {
        "dataSourceId": args.dataSourceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getAgentDataSource.
 */
export interface GetAgentDataSourceArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the data source.
     */
    dataSourceId: string;
}

/**
 * A collection of values returned by getAgentDataSource.
 */
export interface GetAgentDataSourceResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * **DataSourceConfig**
     */
    readonly dataSourceConfigs: outputs.GenerativeAi.GetAgentDataSourceDataSourceConfig[];
    readonly dataSourceId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * A description of the data source.
     */
    readonly description: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable.
     */
    readonly displayName: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the data source.
     */
    readonly id: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the parent KnowledgeBase.
     */
    readonly knowledgeBaseId: string;
    /**
     * A message that describes the current state of the data source in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
     */
    readonly lifecycleDetails: string;
    /**
     * Key-value pairs to allow additional configurations.
     */
    readonly metadata: {[key: string]: string};
    /**
     * The current state of the data source.
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The date and time the data source was created, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    readonly timeCreated: string;
    /**
     * The date and time the data source was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Data Source resource in Oracle Cloud Infrastructure Generative Ai Agent service.
 *
 * **GetDataSource**
 *
 * Gets information about a data source.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDataSource = oci.GenerativeAi.getAgentDataSource({
 *     dataSourceId: testDataSourceOciGenerativeAiAgentDataSource.id,
 * });
 * ```
 */
export function getAgentDataSourceOutput(args: GetAgentDataSourceOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetAgentDataSourceResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:GenerativeAi/getAgentDataSource:getAgentDataSource", {
        "dataSourceId": args.dataSourceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getAgentDataSource.
 */
export interface GetAgentDataSourceOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the data source.
     */
    dataSourceId: pulumi.Input<string>;
}
