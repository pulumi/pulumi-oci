// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waf.Inputs
{

    public sealed class AppFirewallPolicyRequestRateLimitingRuleArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) References action by name from actions defined in WebAppFirewallPolicy.
        /// </summary>
        [Input("actionName", required: true)]
        public Input<string> ActionName { get; set; } = null!;

        /// <summary>
        /// (Updatable) An expression that determines whether or not the rule action should be executed.
        /// </summary>
        [Input("condition")]
        public Input<string>? Condition { get; set; }

        /// <summary>
        /// (Updatable) The language used to parse condition from field `condition`. Available languages:
        /// * **JMESPATH** an extended JMESPath language syntax.
        /// </summary>
        [Input("conditionLanguage")]
        public Input<string>? ConditionLanguage { get; set; }

        [Input("configurations", required: true)]
        private InputList<Inputs.AppFirewallPolicyRequestRateLimitingRuleConfigurationArgs>? _configurations;

        /// <summary>
        /// (Updatable) Rate Limiting Configurations. Each configuration counts requests towards its own `requestsLimit`.
        /// </summary>
        public InputList<Inputs.AppFirewallPolicyRequestRateLimitingRuleConfigurationArgs> Configurations
        {
            get => _configurations ?? (_configurations = new InputList<Inputs.AppFirewallPolicyRequestRateLimitingRuleConfigurationArgs>());
            set => _configurations = value;
        }

        /// <summary>
        /// (Updatable) Rule name. Must be unique within the module.
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        /// <summary>
        /// (Updatable) Type of WebAppFirewallPolicyRule.
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        public AppFirewallPolicyRequestRateLimitingRuleArgs()
        {
        }
        public static new AppFirewallPolicyRequestRateLimitingRuleArgs Empty => new AppFirewallPolicyRequestRateLimitingRuleArgs();
    }
}
