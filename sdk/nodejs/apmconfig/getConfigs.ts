// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Configs in Oracle Cloud Infrastructure Apm Config service.
 *
 * Returns all configuration items, which can optionally be filtered by configuration type.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testConfigs = oci.ApmConfig.getConfigs({
 *     apmDomainId: oci_apm_apm_domain.test_apm_domain.id,
 *     configType: _var.config_config_type,
 *     definedTagEquals: _var.config_defined_tag_equals,
 *     definedTagExists: _var.config_defined_tag_exists,
 *     displayName: _var.config_display_name,
 *     freeformTagEquals: _var.config_freeform_tag_equals,
 *     freeformTagExists: _var.config_freeform_tag_exists,
 *     optionsGroup: _var.config_options_group,
 * });
 * ```
 */
export function getConfigs(args: GetConfigsArgs, opts?: pulumi.InvokeOptions): Promise<GetConfigsResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:ApmConfig/getConfigs:getConfigs", {
        "apmDomainId": args.apmDomainId,
        "configType": args.configType,
        "definedTagEquals": args.definedTagEquals,
        "definedTagExists": args.definedTagExists,
        "displayName": args.displayName,
        "filters": args.filters,
        "freeformTagEquals": args.freeformTagEquals,
        "freeformTagExists": args.freeformTagExists,
        "optionsGroup": args.optionsGroup,
    }, opts);
}

/**
 * A collection of arguments for invoking getConfigs.
 */
export interface GetConfigsArgs {
    /**
     * The APM Domain ID the request is intended for.
     */
    apmDomainId: string;
    /**
     * A filter to match configuration items of a given type. Supported values are SPAN_FILTER, METRIC_GROUP, and APDEX.
     */
    configType?: string;
    /**
     * A list of tag filters to apply.  Only resources with a defined tag matching the value will be returned. Each item in the list has the format "{namespace}.{tagName}.{value}".  All inputs are case-insensitive. Multiple values for the same key (i.e. same namespace and tag name) are interpreted as "OR". Values for different keys (i.e. different namespaces, different tag names, or both) are interpreted as "AND".
     */
    definedTagEquals?: string[];
    /**
     * A list of tag existence filters to apply.  Only resources for which the specified defined tags exist will be returned. Each item in the list has the format "{namespace}.{tagName}.true" (for checking existence of a defined tag) or "{namespace}.true".  All inputs are case-insensitive. Currently, only existence ("true" at the end) is supported. Absence ("false" at the end) is not supported. Multiple values for the same key (i.e. same namespace and tag name) are interpreted as "OR". Values for different keys (i.e. different namespaces, different tag names, or both) are interpreted as "AND".
     */
    definedTagExists?: string[];
    /**
     * A filter to return resources that match the given display name.
     */
    displayName?: string;
    filters?: inputs.ApmConfig.GetConfigsFilter[];
    /**
     * A list of tag filters to apply.  Only resources with a freeform tag matching the value will be returned. The key for each tag is "{tagName}.{value}".  All inputs are case-insensitive. Multiple values for the same tag name are interpreted as "OR".  Values for different tag names are interpreted as "AND".
     */
    freeformTagEquals?: string[];
    /**
     * A list of tag existence filters to apply.  Only resources for which the specified freeform tags exist the value will be returned. The key for each tag is "{tagName}.true".  All inputs are case-insensitive. Currently, only existence ("true" at the end) is supported. Absence ("false" at the end) is not supported. Multiple values for different tag names are interpreted as "AND".
     */
    freeformTagExists?: string[];
    /**
     * A filter to return OPTIONS resources that match the given group.
     */
    optionsGroup?: string;
}

/**
 * A collection of values returned by getConfigs.
 */
export interface GetConfigsResult {
    readonly apmDomainId: string;
    /**
     * The list of config_collection.
     */
    readonly configCollections: outputs.ApmConfig.GetConfigsConfigCollection[];
    /**
     * The type of configuration item.
     */
    readonly configType?: string;
    readonly definedTagEquals?: string[];
    readonly definedTagExists?: string[];
    /**
     * The name by which a configuration entity is displayed to the end user.
     */
    readonly displayName?: string;
    readonly filters?: outputs.ApmConfig.GetConfigsFilter[];
    readonly freeformTagEquals?: string[];
    readonly freeformTagExists?: string[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly optionsGroup?: string;
}

export function getConfigsOutput(args: GetConfigsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetConfigsResult> {
    return pulumi.output(args).apply(a => getConfigs(a, opts))
}

/**
 * A collection of arguments for invoking getConfigs.
 */
export interface GetConfigsOutputArgs {
    /**
     * The APM Domain ID the request is intended for.
     */
    apmDomainId: pulumi.Input<string>;
    /**
     * A filter to match configuration items of a given type. Supported values are SPAN_FILTER, METRIC_GROUP, and APDEX.
     */
    configType?: pulumi.Input<string>;
    /**
     * A list of tag filters to apply.  Only resources with a defined tag matching the value will be returned. Each item in the list has the format "{namespace}.{tagName}.{value}".  All inputs are case-insensitive. Multiple values for the same key (i.e. same namespace and tag name) are interpreted as "OR". Values for different keys (i.e. different namespaces, different tag names, or both) are interpreted as "AND".
     */
    definedTagEquals?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A list of tag existence filters to apply.  Only resources for which the specified defined tags exist will be returned. Each item in the list has the format "{namespace}.{tagName}.true" (for checking existence of a defined tag) or "{namespace}.true".  All inputs are case-insensitive. Currently, only existence ("true" at the end) is supported. Absence ("false" at the end) is not supported. Multiple values for the same key (i.e. same namespace and tag name) are interpreted as "OR". Values for different keys (i.e. different namespaces, different tag names, or both) are interpreted as "AND".
     */
    definedTagExists?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return resources that match the given display name.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.ApmConfig.GetConfigsFilterArgs>[]>;
    /**
     * A list of tag filters to apply.  Only resources with a freeform tag matching the value will be returned. The key for each tag is "{tagName}.{value}".  All inputs are case-insensitive. Multiple values for the same tag name are interpreted as "OR".  Values for different tag names are interpreted as "AND".
     */
    freeformTagEquals?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A list of tag existence filters to apply.  Only resources for which the specified freeform tags exist the value will be returned. The key for each tag is "{tagName}.true".  All inputs are case-insensitive. Currently, only existence ("true" at the end) is supported. Absence ("false" at the end) is not supported. Multiple values for different tag names are interpreted as "AND".
     */
    freeformTagExists?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return OPTIONS resources that match the given group.
     */
    optionsGroup?: pulumi.Input<string>;
}