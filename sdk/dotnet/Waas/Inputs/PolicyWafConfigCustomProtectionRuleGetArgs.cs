// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Inputs
{

    public sealed class PolicyWafConfigCustomProtectionRuleGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The action to take against requests from detected bots. If unspecified, defaults to `DETECT`.
        /// </summary>
        [Input("action")]
        public Input<string>? Action { get; set; }

        [Input("exclusions")]
        private InputList<Inputs.PolicyWafConfigCustomProtectionRuleExclusionGetArgs>? _exclusions;

        /// <summary>
        /// (Updatable) An array of The target property of a request that would allow it to bypass the protection rule. For example, when `target` is `REQUEST_COOKIE_NAMES`, the list may include names of cookies to exclude from the protection rule. When the target is `ARGS`, the list may include strings of URL query parameters and values from form-urlencoded XML, JSON, AMP, or POST payloads to exclude from the protection rule. `Exclusions` properties must not contain whitespace, comma or |. **Note:** If protection rules have been enabled that utilize the `maxArgumentCount` or `maxTotalNameLengthOfArguments` properties, and the `target` property has been set to `ARGS`, it is important that the `exclusions` properties be defined to honor those protection rule settings in a consistent manner.
        /// </summary>
        public InputList<Inputs.PolicyWafConfigCustomProtectionRuleExclusionGetArgs> Exclusions
        {
            get => _exclusions ?? (_exclusions = new InputList<Inputs.PolicyWafConfigCustomProtectionRuleExclusionGetArgs>());
            set => _exclusions = value;
        }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the custom protection rule.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        public PolicyWafConfigCustomProtectionRuleGetArgs()
        {
        }
        public static new PolicyWafConfigCustomProtectionRuleGetArgs Empty => new PolicyWafConfigCustomProtectionRuleGetArgs();
    }
}