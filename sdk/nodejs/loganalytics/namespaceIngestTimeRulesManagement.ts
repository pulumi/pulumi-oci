// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Namespace Ingest Time Rules Management resource in Oracle Cloud Infrastructure Log Analytics service.
 *
 * Enables the specified ingest time rule.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNamespaceIngestTimeRulesManagement = new oci.loganalytics.NamespaceIngestTimeRulesManagement("test_namespace_ingest_time_rules_management", {
 *     ingestTimeRuleId: testRule.id,
 *     namespace: namespaceIngestTimeRulesManagementNamespace,
 *     enableIngestTimeRule: enableIngestTimeRule,
 * });
 * ```
 */
export class NamespaceIngestTimeRulesManagement extends pulumi.CustomResource {
    /**
     * Get an existing NamespaceIngestTimeRulesManagement resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: NamespaceIngestTimeRulesManagementState, opts?: pulumi.CustomResourceOptions): NamespaceIngestTimeRulesManagement {
        return new NamespaceIngestTimeRulesManagement(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:LogAnalytics/namespaceIngestTimeRulesManagement:NamespaceIngestTimeRulesManagement';

    /**
     * Returns true if the given object is an instance of NamespaceIngestTimeRulesManagement.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is NamespaceIngestTimeRulesManagement {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === NamespaceIngestTimeRulesManagement.__pulumiType;
    }

    /**
     * (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly enableIngestTimeRule!: pulumi.Output<boolean>;
    /**
     * Unique ocid of the ingest time rule.
     */
    public readonly ingestTimeRuleId!: pulumi.Output<string>;
    /**
     * The Logging Analytics namespace used for the request.
     */
    public readonly namespace!: pulumi.Output<string>;

    /**
     * Create a NamespaceIngestTimeRulesManagement resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: NamespaceIngestTimeRulesManagementArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: NamespaceIngestTimeRulesManagementArgs | NamespaceIngestTimeRulesManagementState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as NamespaceIngestTimeRulesManagementState | undefined;
            resourceInputs["enableIngestTimeRule"] = state ? state.enableIngestTimeRule : undefined;
            resourceInputs["ingestTimeRuleId"] = state ? state.ingestTimeRuleId : undefined;
            resourceInputs["namespace"] = state ? state.namespace : undefined;
        } else {
            const args = argsOrState as NamespaceIngestTimeRulesManagementArgs | undefined;
            if ((!args || args.enableIngestTimeRule === undefined) && !opts.urn) {
                throw new Error("Missing required property 'enableIngestTimeRule'");
            }
            if ((!args || args.ingestTimeRuleId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'ingestTimeRuleId'");
            }
            if ((!args || args.namespace === undefined) && !opts.urn) {
                throw new Error("Missing required property 'namespace'");
            }
            resourceInputs["enableIngestTimeRule"] = args ? args.enableIngestTimeRule : undefined;
            resourceInputs["ingestTimeRuleId"] = args ? args.ingestTimeRuleId : undefined;
            resourceInputs["namespace"] = args ? args.namespace : undefined;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(NamespaceIngestTimeRulesManagement.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering NamespaceIngestTimeRulesManagement resources.
 */
export interface NamespaceIngestTimeRulesManagementState {
    /**
     * (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    enableIngestTimeRule?: pulumi.Input<boolean>;
    /**
     * Unique ocid of the ingest time rule.
     */
    ingestTimeRuleId?: pulumi.Input<string>;
    /**
     * The Logging Analytics namespace used for the request.
     */
    namespace?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a NamespaceIngestTimeRulesManagement resource.
 */
export interface NamespaceIngestTimeRulesManagementArgs {
    /**
     * (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    enableIngestTimeRule: pulumi.Input<boolean>;
    /**
     * Unique ocid of the ingest time rule.
     */
    ingestTimeRuleId: pulumi.Input<string>;
    /**
     * The Logging Analytics namespace used for the request.
     */
    namespace: pulumi.Input<string>;
}
