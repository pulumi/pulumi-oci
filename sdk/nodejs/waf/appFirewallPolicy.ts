// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Web App Firewall Policy resource in Oracle Cloud Infrastructure Waf service.
 *
 * Creates a new WebAppFirewallPolicy.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testWebAppFirewallPolicy = new oci.waf.AppFirewallPolicy("testWebAppFirewallPolicy", {
 *     compartmentId: _var.compartment_id,
 *     actions: [{
 *         name: _var.web_app_firewall_policy_actions_name,
 *         type: _var.web_app_firewall_policy_actions_type,
 *         body: {
 *             text: _var.web_app_firewall_policy_actions_body_text,
 *             type: _var.web_app_firewall_policy_actions_body_type,
 *         },
 *         code: _var.web_app_firewall_policy_actions_code,
 *         headers: [{
 *             name: _var.web_app_firewall_policy_actions_headers_name,
 *             value: _var.web_app_firewall_policy_actions_headers_value,
 *         }],
 *     }],
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     displayName: _var.web_app_firewall_policy_display_name,
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 *     requestAccessControl: {
 *         defaultActionName: _var.web_app_firewall_policy_request_access_control_default_action_name,
 *         rules: [{
 *             actionName: _var.web_app_firewall_policy_request_access_control_rules_action_name,
 *             name: _var.web_app_firewall_policy_request_access_control_rules_name,
 *             type: _var.web_app_firewall_policy_request_access_control_rules_type,
 *             condition: _var.web_app_firewall_policy_request_access_control_rules_condition,
 *             conditionLanguage: _var.web_app_firewall_policy_request_access_control_rules_condition_language,
 *         }],
 *     },
 *     requestProtection: {
 *         bodyInspectionSizeLimitExceededActionName: _var.web_app_firewall_policy_request_protection_body_inspection_size_limit_exceeded_action_name,
 *         bodyInspectionSizeLimitInBytes: _var.web_app_firewall_policy_request_protection_body_inspection_size_limit_in_bytes,
 *         rules: [{
 *             actionName: _var.web_app_firewall_policy_request_protection_rules_action_name,
 *             name: _var.web_app_firewall_policy_request_protection_rules_name,
 *             protectionCapabilities: [{
 *                 key: _var.web_app_firewall_policy_request_protection_rules_protection_capabilities_key,
 *                 version: _var.web_app_firewall_policy_request_protection_rules_protection_capabilities_version,
 *                 actionName: _var.web_app_firewall_policy_request_protection_rules_protection_capabilities_action_name,
 *                 collaborativeActionThreshold: _var.web_app_firewall_policy_request_protection_rules_protection_capabilities_collaborative_action_threshold,
 *                 collaborativeWeights: [{
 *                     key: _var.web_app_firewall_policy_request_protection_rules_protection_capabilities_collaborative_weights_key,
 *                     weight: _var.web_app_firewall_policy_request_protection_rules_protection_capabilities_collaborative_weights_weight,
 *                 }],
 *                 exclusions: {
 *                     args: _var.web_app_firewall_policy_request_protection_rules_protection_capabilities_exclusions_args,
 *                     requestCookies: _var.web_app_firewall_policy_request_protection_rules_protection_capabilities_exclusions_request_cookies,
 *                 },
 *             }],
 *             type: _var.web_app_firewall_policy_request_protection_rules_type,
 *             condition: _var.web_app_firewall_policy_request_protection_rules_condition,
 *             conditionLanguage: _var.web_app_firewall_policy_request_protection_rules_condition_language,
 *             isBodyInspectionEnabled: _var.web_app_firewall_policy_request_protection_rules_is_body_inspection_enabled,
 *             protectionCapabilitySettings: {
 *                 allowedHttpMethods: _var.web_app_firewall_policy_request_protection_rules_protection_capability_settings_allowed_http_methods,
 *                 maxHttpRequestHeaderLength: _var.web_app_firewall_policy_request_protection_rules_protection_capability_settings_max_http_request_header_length,
 *                 maxHttpRequestHeaders: _var.web_app_firewall_policy_request_protection_rules_protection_capability_settings_max_http_request_headers,
 *                 maxNumberOfArguments: _var.web_app_firewall_policy_request_protection_rules_protection_capability_settings_max_number_of_arguments,
 *                 maxSingleArgumentLength: _var.web_app_firewall_policy_request_protection_rules_protection_capability_settings_max_single_argument_length,
 *                 maxTotalArgumentLength: _var.web_app_firewall_policy_request_protection_rules_protection_capability_settings_max_total_argument_length,
 *             },
 *         }],
 *     },
 *     requestRateLimiting: {
 *         rules: [{
 *             actionName: _var.web_app_firewall_policy_request_rate_limiting_rules_action_name,
 *             configurations: [{
 *                 periodInSeconds: _var.web_app_firewall_policy_request_rate_limiting_rules_configurations_period_in_seconds,
 *                 requestsLimit: _var.web_app_firewall_policy_request_rate_limiting_rules_configurations_requests_limit,
 *                 actionDurationInSeconds: _var.web_app_firewall_policy_request_rate_limiting_rules_configurations_action_duration_in_seconds,
 *             }],
 *             name: _var.web_app_firewall_policy_request_rate_limiting_rules_name,
 *             type: _var.web_app_firewall_policy_request_rate_limiting_rules_type,
 *             condition: _var.web_app_firewall_policy_request_rate_limiting_rules_condition,
 *             conditionLanguage: _var.web_app_firewall_policy_request_rate_limiting_rules_condition_language,
 *         }],
 *     },
 *     responseAccessControl: {
 *         rules: [{
 *             actionName: _var.web_app_firewall_policy_response_access_control_rules_action_name,
 *             name: _var.web_app_firewall_policy_response_access_control_rules_name,
 *             type: _var.web_app_firewall_policy_response_access_control_rules_type,
 *             condition: _var.web_app_firewall_policy_response_access_control_rules_condition,
 *             conditionLanguage: _var.web_app_firewall_policy_response_access_control_rules_condition_language,
 *         }],
 *     },
 *     responseProtection: {
 *         rules: [{
 *             actionName: _var.web_app_firewall_policy_response_protection_rules_action_name,
 *             name: _var.web_app_firewall_policy_response_protection_rules_name,
 *             protectionCapabilities: [{
 *                 key: _var.web_app_firewall_policy_response_protection_rules_protection_capabilities_key,
 *                 version: _var.web_app_firewall_policy_response_protection_rules_protection_capabilities_version,
 *                 actionName: _var.web_app_firewall_policy_response_protection_rules_protection_capabilities_action_name,
 *                 collaborativeActionThreshold: _var.web_app_firewall_policy_response_protection_rules_protection_capabilities_collaborative_action_threshold,
 *                 collaborativeWeights: [{
 *                     key: _var.web_app_firewall_policy_response_protection_rules_protection_capabilities_collaborative_weights_key,
 *                     weight: _var.web_app_firewall_policy_response_protection_rules_protection_capabilities_collaborative_weights_weight,
 *                 }],
 *                 exclusions: {
 *                     args: _var.web_app_firewall_policy_response_protection_rules_protection_capabilities_exclusions_args,
 *                     requestCookies: _var.web_app_firewall_policy_response_protection_rules_protection_capabilities_exclusions_request_cookies,
 *                 },
 *             }],
 *             type: _var.web_app_firewall_policy_response_protection_rules_type,
 *             condition: _var.web_app_firewall_policy_response_protection_rules_condition,
 *             conditionLanguage: _var.web_app_firewall_policy_response_protection_rules_condition_language,
 *             isBodyInspectionEnabled: _var.web_app_firewall_policy_response_protection_rules_is_body_inspection_enabled,
 *             protectionCapabilitySettings: {
 *                 allowedHttpMethods: _var.web_app_firewall_policy_response_protection_rules_protection_capability_settings_allowed_http_methods,
 *                 maxHttpRequestHeaderLength: _var.web_app_firewall_policy_response_protection_rules_protection_capability_settings_max_http_request_header_length,
 *                 maxHttpRequestHeaders: _var.web_app_firewall_policy_response_protection_rules_protection_capability_settings_max_http_request_headers,
 *                 maxNumberOfArguments: _var.web_app_firewall_policy_response_protection_rules_protection_capability_settings_max_number_of_arguments,
 *                 maxSingleArgumentLength: _var.web_app_firewall_policy_response_protection_rules_protection_capability_settings_max_single_argument_length,
 *                 maxTotalArgumentLength: _var.web_app_firewall_policy_response_protection_rules_protection_capability_settings_max_total_argument_length,
 *             },
 *         }],
 *     },
 *     systemTags: _var.web_app_firewall_policy_system_tags,
 * });
 * ```
 *
 * ## Import
 *
 * WebAppFirewallPolicies can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:Waf/appFirewallPolicy:AppFirewallPolicy test_web_app_firewall_policy "id"
 * ```
 */
export class AppFirewallPolicy extends pulumi.CustomResource {
    /**
     * Get an existing AppFirewallPolicy resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: AppFirewallPolicyState, opts?: pulumi.CustomResourceOptions): AppFirewallPolicy {
        return new AppFirewallPolicy(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Waf/appFirewallPolicy:AppFirewallPolicy';

    /**
     * Returns true if the given object is an instance of AppFirewallPolicy.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is AppFirewallPolicy {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === AppFirewallPolicy.__pulumiType;
    }

    /**
     * (Updatable) Predefined actions for use in multiple different rules. Not all actions are supported in every module. Some actions terminate further execution of modules and rules in a module and some do not. Actions names must be unique within this array.
     */
    public readonly actions!: pulumi.Output<outputs.Waf.AppFirewallPolicyAction[]>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) WebAppFirewallPolicy display name, can be renamed.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in FAILED state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * (Updatable) Module that allows inspection of HTTP request properties and to return a defined HTTP response. In this module, rules with the name 'Default Action' are not allowed, since this name is reserved for default action logs.
     */
    public readonly requestAccessControl!: pulumi.Output<outputs.Waf.AppFirewallPolicyRequestAccessControl>;
    /**
     * (Updatable) Module that allows to enable OCI-managed protection capabilities for incoming HTTP requests.
     */
    public readonly requestProtection!: pulumi.Output<outputs.Waf.AppFirewallPolicyRequestProtection>;
    /**
     * (Updatable) Module that allows inspection of HTTP connection properties and to limit requests frequency for a given key.
     */
    public readonly requestRateLimiting!: pulumi.Output<outputs.Waf.AppFirewallPolicyRequestRateLimiting>;
    /**
     * (Updatable) Module that allows inspection of HTTP response properties and to return a defined HTTP response.
     */
    public readonly responseAccessControl!: pulumi.Output<outputs.Waf.AppFirewallPolicyResponseAccessControl>;
    /**
     * (Updatable) Module that allows to enable OCI-managed protection capabilities for HTTP responses.
     */
    public readonly responseProtection!: pulumi.Output<outputs.Waf.AppFirewallPolicyResponseProtection>;
    /**
     * The current state of the WebAppFirewallPolicy.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * (Updatable) Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public readonly systemTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The time the WebAppFirewallPolicy was created. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time the WebAppFirewallPolicy was updated. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a AppFirewallPolicy resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: AppFirewallPolicyArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: AppFirewallPolicyArgs | AppFirewallPolicyState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as AppFirewallPolicyState | undefined;
            resourceInputs["actions"] = state ? state.actions : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["requestAccessControl"] = state ? state.requestAccessControl : undefined;
            resourceInputs["requestProtection"] = state ? state.requestProtection : undefined;
            resourceInputs["requestRateLimiting"] = state ? state.requestRateLimiting : undefined;
            resourceInputs["responseAccessControl"] = state ? state.responseAccessControl : undefined;
            resourceInputs["responseProtection"] = state ? state.responseProtection : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as AppFirewallPolicyArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            resourceInputs["actions"] = args ? args.actions : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["requestAccessControl"] = args ? args.requestAccessControl : undefined;
            resourceInputs["requestProtection"] = args ? args.requestProtection : undefined;
            resourceInputs["requestRateLimiting"] = args ? args.requestRateLimiting : undefined;
            resourceInputs["responseAccessControl"] = args ? args.responseAccessControl : undefined;
            resourceInputs["responseProtection"] = args ? args.responseProtection : undefined;
            resourceInputs["systemTags"] = args ? args.systemTags : undefined;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(AppFirewallPolicy.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering AppFirewallPolicy resources.
 */
export interface AppFirewallPolicyState {
    /**
     * (Updatable) Predefined actions for use in multiple different rules. Not all actions are supported in every module. Some actions terminate further execution of modules and rules in a module and some do not. Actions names must be unique within this array.
     */
    actions?: pulumi.Input<pulumi.Input<inputs.Waf.AppFirewallPolicyAction>[]>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) WebAppFirewallPolicy display name, can be renamed.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in FAILED state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * (Updatable) Module that allows inspection of HTTP request properties and to return a defined HTTP response. In this module, rules with the name 'Default Action' are not allowed, since this name is reserved for default action logs.
     */
    requestAccessControl?: pulumi.Input<inputs.Waf.AppFirewallPolicyRequestAccessControl>;
    /**
     * (Updatable) Module that allows to enable OCI-managed protection capabilities for incoming HTTP requests.
     */
    requestProtection?: pulumi.Input<inputs.Waf.AppFirewallPolicyRequestProtection>;
    /**
     * (Updatable) Module that allows inspection of HTTP connection properties and to limit requests frequency for a given key.
     */
    requestRateLimiting?: pulumi.Input<inputs.Waf.AppFirewallPolicyRequestRateLimiting>;
    /**
     * (Updatable) Module that allows inspection of HTTP response properties and to return a defined HTTP response.
     */
    responseAccessControl?: pulumi.Input<inputs.Waf.AppFirewallPolicyResponseAccessControl>;
    /**
     * (Updatable) Module that allows to enable OCI-managed protection capabilities for HTTP responses.
     */
    responseProtection?: pulumi.Input<inputs.Waf.AppFirewallPolicyResponseProtection>;
    /**
     * The current state of the WebAppFirewallPolicy.
     */
    state?: pulumi.Input<string>;
    /**
     * (Updatable) Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The time the WebAppFirewallPolicy was created. An RFC3339 formatted datetime string.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time the WebAppFirewallPolicy was updated. An RFC3339 formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a AppFirewallPolicy resource.
 */
export interface AppFirewallPolicyArgs {
    /**
     * (Updatable) Predefined actions for use in multiple different rules. Not all actions are supported in every module. Some actions terminate further execution of modules and rules in a module and some do not. Actions names must be unique within this array.
     */
    actions?: pulumi.Input<pulumi.Input<inputs.Waf.AppFirewallPolicyAction>[]>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) WebAppFirewallPolicy display name, can be renamed.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) Module that allows inspection of HTTP request properties and to return a defined HTTP response. In this module, rules with the name 'Default Action' are not allowed, since this name is reserved for default action logs.
     */
    requestAccessControl?: pulumi.Input<inputs.Waf.AppFirewallPolicyRequestAccessControl>;
    /**
     * (Updatable) Module that allows to enable OCI-managed protection capabilities for incoming HTTP requests.
     */
    requestProtection?: pulumi.Input<inputs.Waf.AppFirewallPolicyRequestProtection>;
    /**
     * (Updatable) Module that allows inspection of HTTP connection properties and to limit requests frequency for a given key.
     */
    requestRateLimiting?: pulumi.Input<inputs.Waf.AppFirewallPolicyRequestRateLimiting>;
    /**
     * (Updatable) Module that allows inspection of HTTP response properties and to return a defined HTTP response.
     */
    responseAccessControl?: pulumi.Input<inputs.Waf.AppFirewallPolicyResponseAccessControl>;
    /**
     * (Updatable) Module that allows to enable OCI-managed protection capabilities for HTTP responses.
     */
    responseProtection?: pulumi.Input<inputs.Waf.AppFirewallPolicyResponseProtection>;
    /**
     * (Updatable) Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: any}>;
}