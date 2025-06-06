// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Namespace Templates in Oracle Cloud Infrastructure Log Analytics service.
 *
 * Returns a list of templates, containing detailed information about them. You may limit the number of results, provide sorting order, and filter by information such as template name, type, display name and description.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNamespaceTemplates = oci.LogAnalytics.getNamespaceTemplates({
 *     compartmentId: compartmentId,
 *     namespace: namespaceTemplateNamespace,
 *     name: namespaceTemplateName,
 *     namespaceTemplateFilter: namespaceTemplateNamespaceTemplateFilter,
 *     state: namespaceTemplateState,
 *     templateDisplayText: namespaceTemplateTemplateDisplayText,
 *     type: namespaceTemplateType,
 * });
 * ```
 */
export function getNamespaceTemplates(args: GetNamespaceTemplatesArgs, opts?: pulumi.InvokeOptions): Promise<GetNamespaceTemplatesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:LogAnalytics/getNamespaceTemplates:getNamespaceTemplates", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "name": args.name,
        "namespace": args.namespace,
        "namespaceTemplateFilter": args.namespaceTemplateFilter,
        "state": args.state,
        "templateDisplayText": args.templateDisplayText,
        "type": args.type,
    }, opts);
}

/**
 * A collection of arguments for invoking getNamespaceTemplates.
 */
export interface GetNamespaceTemplatesArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: string;
    filters?: inputs.LogAnalytics.GetNamespaceTemplatesFilter[];
    /**
     * The template name used for filtering.
     */
    name?: string;
    /**
     * The Logging Analytics namespace used for the request.
     */
    namespace: string;
    /**
     * filter
     */
    namespaceTemplateFilter?: string;
    /**
     * The template lifecycle state used for filtering. Currently supported values are ACTIVE and DELETED.
     */
    state?: string;
    /**
     * The template display text used for filtering. Only templates with the specified name or description will be returned.
     */
    templateDisplayText?: string;
    /**
     * The template type used for filtering. Only templates of the specified type will be returned.
     */
    type?: string;
}

/**
 * A collection of values returned by getNamespaceTemplates.
 */
export interface GetNamespaceTemplatesResult {
    /**
     * Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    readonly compartmentId: string;
    readonly filters?: outputs.LogAnalytics.GetNamespaceTemplatesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of log_analytics_template_collection.
     */
    readonly logAnalyticsTemplateCollections: outputs.LogAnalytics.GetNamespaceTemplatesLogAnalyticsTemplateCollection[];
    /**
     * The template name.
     */
    readonly name?: string;
    readonly namespace: string;
    readonly namespaceTemplateFilter?: string;
    /**
     * The current state of the template.
     */
    readonly state?: string;
    readonly templateDisplayText?: string;
    /**
     * The template type.
     */
    readonly type?: string;
}
/**
 * This data source provides the list of Namespace Templates in Oracle Cloud Infrastructure Log Analytics service.
 *
 * Returns a list of templates, containing detailed information about them. You may limit the number of results, provide sorting order, and filter by information such as template name, type, display name and description.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNamespaceTemplates = oci.LogAnalytics.getNamespaceTemplates({
 *     compartmentId: compartmentId,
 *     namespace: namespaceTemplateNamespace,
 *     name: namespaceTemplateName,
 *     namespaceTemplateFilter: namespaceTemplateNamespaceTemplateFilter,
 *     state: namespaceTemplateState,
 *     templateDisplayText: namespaceTemplateTemplateDisplayText,
 *     type: namespaceTemplateType,
 * });
 * ```
 */
export function getNamespaceTemplatesOutput(args: GetNamespaceTemplatesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetNamespaceTemplatesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:LogAnalytics/getNamespaceTemplates:getNamespaceTemplates", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "name": args.name,
        "namespace": args.namespace,
        "namespaceTemplateFilter": args.namespaceTemplateFilter,
        "state": args.state,
        "templateDisplayText": args.templateDisplayText,
        "type": args.type,
    }, opts);
}

/**
 * A collection of arguments for invoking getNamespaceTemplates.
 */
export interface GetNamespaceTemplatesOutputArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.LogAnalytics.GetNamespaceTemplatesFilterArgs>[]>;
    /**
     * The template name used for filtering.
     */
    name?: pulumi.Input<string>;
    /**
     * The Logging Analytics namespace used for the request.
     */
    namespace: pulumi.Input<string>;
    /**
     * filter
     */
    namespaceTemplateFilter?: pulumi.Input<string>;
    /**
     * The template lifecycle state used for filtering. Currently supported values are ACTIVE and DELETED.
     */
    state?: pulumi.Input<string>;
    /**
     * The template display text used for filtering. Only templates with the specified name or description will be returned.
     */
    templateDisplayText?: pulumi.Input<string>;
    /**
     * The template type used for filtering. Only templates of the specified type will be returned.
     */
    type?: pulumi.Input<string>;
}
