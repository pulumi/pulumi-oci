// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Protection Rule resource in Oracle Cloud Infrastructure Web Application Acceleration and Security service.
 *
 * Updates the action for each specified protection rule. Requests can either be allowed, blocked, or trigger an alert if they meet the parameters of an applied rule. For more information on protection rules, see [WAF Protection Rules](https://docs.cloud.oracle.com/iaas/Content/WAF/Tasks/wafprotectionrules.htm).
 * This operation can update or disable protection rules depending on the structure of the request body.
 * Protection rules can be updated by changing the properties of the protection rule object with the rule's key specified in the key field.
 *
 * ## Import
 *
 * ProtectionRules can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:Waas/protectionRule:ProtectionRule test_protection_rule "waasPolicyId/{waasPolicyId}/key/{key}"
 * ```
 */
export class ProtectionRule extends pulumi.CustomResource {
    /**
     * Get an existing ProtectionRule resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ProtectionRuleState, opts?: pulumi.CustomResourceOptions): ProtectionRule {
        return new ProtectionRule(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Waas/protectionRule:ProtectionRule';

    /**
     * Returns true if the given object is an instance of ProtectionRule.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ProtectionRule {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ProtectionRule.__pulumiType;
    }

    /**
     * (Updatable) The action to take when the traffic is detected as malicious. If unspecified, defaults to `OFF`.
     */
    public readonly action!: pulumi.Output<string>;
    /**
     * The description of the protection rule.
     */
    public /*out*/ readonly description!: pulumi.Output<string>;
    /**
     * An array of The target property of a request that would allow it to bypass the protection rule. For example, when `target` is `REQUEST_COOKIE_NAMES`, the list may include names of cookies to exclude from the protection rule. When the target is `ARGS`, the list may include strings of URL query parameters and values from form-urlencoded XML, JSON, AMP, or POST payloads to exclude from the protection rule. `Exclusions` properties must not contain whitespace, comma or |. **Note:** If protection rules have been enabled that utilize the `maxArgumentCount` or `maxTotalNameLengthOfArguments` properties, and the `target` property has been set to `ARGS`, it is important that the `exclusions` properties be defined to honor those protection rule settings in a consistent manner.
     */
    public readonly exclusions!: pulumi.Output<outputs.Waas.ProtectionRuleExclusion[]>;
    /**
     * (Updatable) The unique key of the protection rule.
     */
    public readonly key!: pulumi.Output<string>;
    /**
     * The list of labels for the protection rule.
     */
    public /*out*/ readonly labels!: pulumi.Output<string[]>;
    /**
     * The list of the ModSecurity rule IDs that apply to this protection rule. For more information about ModSecurity's open source WAF rules, see [Mod Security's documentation](https://www.modsecurity.org/CRS/Documentation/index.html).
     */
    public /*out*/ readonly modSecurityRuleIds!: pulumi.Output<string[]>;
    /**
     * The name of the protection rule.
     */
    public /*out*/ readonly name!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
     */
    public readonly waasPolicyId!: pulumi.Output<string>;

    /**
     * Create a ProtectionRule resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ProtectionRuleArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ProtectionRuleArgs | ProtectionRuleState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ProtectionRuleState | undefined;
            resourceInputs["action"] = state ? state.action : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["exclusions"] = state ? state.exclusions : undefined;
            resourceInputs["key"] = state ? state.key : undefined;
            resourceInputs["labels"] = state ? state.labels : undefined;
            resourceInputs["modSecurityRuleIds"] = state ? state.modSecurityRuleIds : undefined;
            resourceInputs["name"] = state ? state.name : undefined;
            resourceInputs["waasPolicyId"] = state ? state.waasPolicyId : undefined;
        } else {
            const args = argsOrState as ProtectionRuleArgs | undefined;
            if ((!args || args.key === undefined) && !opts.urn) {
                throw new Error("Missing required property 'key'");
            }
            if ((!args || args.waasPolicyId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'waasPolicyId'");
            }
            resourceInputs["action"] = args ? args.action : undefined;
            resourceInputs["exclusions"] = args ? args.exclusions : undefined;
            resourceInputs["key"] = args ? args.key : undefined;
            resourceInputs["waasPolicyId"] = args ? args.waasPolicyId : undefined;
            resourceInputs["description"] = undefined /*out*/;
            resourceInputs["labels"] = undefined /*out*/;
            resourceInputs["modSecurityRuleIds"] = undefined /*out*/;
            resourceInputs["name"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ProtectionRule.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ProtectionRule resources.
 */
export interface ProtectionRuleState {
    /**
     * (Updatable) The action to take when the traffic is detected as malicious. If unspecified, defaults to `OFF`.
     */
    action?: pulumi.Input<string>;
    /**
     * The description of the protection rule.
     */
    description?: pulumi.Input<string>;
    /**
     * An array of The target property of a request that would allow it to bypass the protection rule. For example, when `target` is `REQUEST_COOKIE_NAMES`, the list may include names of cookies to exclude from the protection rule. When the target is `ARGS`, the list may include strings of URL query parameters and values from form-urlencoded XML, JSON, AMP, or POST payloads to exclude from the protection rule. `Exclusions` properties must not contain whitespace, comma or |. **Note:** If protection rules have been enabled that utilize the `maxArgumentCount` or `maxTotalNameLengthOfArguments` properties, and the `target` property has been set to `ARGS`, it is important that the `exclusions` properties be defined to honor those protection rule settings in a consistent manner.
     */
    exclusions?: pulumi.Input<pulumi.Input<inputs.Waas.ProtectionRuleExclusion>[]>;
    /**
     * (Updatable) The unique key of the protection rule.
     */
    key?: pulumi.Input<string>;
    /**
     * The list of labels for the protection rule.
     */
    labels?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The list of the ModSecurity rule IDs that apply to this protection rule. For more information about ModSecurity's open source WAF rules, see [Mod Security's documentation](https://www.modsecurity.org/CRS/Documentation/index.html).
     */
    modSecurityRuleIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The name of the protection rule.
     */
    name?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
     */
    waasPolicyId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ProtectionRule resource.
 */
export interface ProtectionRuleArgs {
    /**
     * (Updatable) The action to take when the traffic is detected as malicious. If unspecified, defaults to `OFF`.
     */
    action?: pulumi.Input<string>;
    /**
     * An array of The target property of a request that would allow it to bypass the protection rule. For example, when `target` is `REQUEST_COOKIE_NAMES`, the list may include names of cookies to exclude from the protection rule. When the target is `ARGS`, the list may include strings of URL query parameters and values from form-urlencoded XML, JSON, AMP, or POST payloads to exclude from the protection rule. `Exclusions` properties must not contain whitespace, comma or |. **Note:** If protection rules have been enabled that utilize the `maxArgumentCount` or `maxTotalNameLengthOfArguments` properties, and the `target` property has been set to `ARGS`, it is important that the `exclusions` properties be defined to honor those protection rule settings in a consistent manner.
     */
    exclusions?: pulumi.Input<pulumi.Input<inputs.Waas.ProtectionRuleExclusion>[]>;
    /**
     * (Updatable) The unique key of the protection rule.
     */
    key: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
     */
    waasPolicyId: pulumi.Input<string>;
}