// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waf.Inputs
{

    public sealed class AppFirewallPolicyRequestProtectionRuleGetArgs : global::Pulumi.ResourceArgs
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

        /// <summary>
        /// (Updatable) Enables/disables body inspection for this protection rule. Only Protection Rules in RequestProtection can have this option enabled. Response body inspection will be available at a later date.
        /// </summary>
        [Input("isBodyInspectionEnabled")]
        public Input<bool>? IsBodyInspectionEnabled { get; set; }

        /// <summary>
        /// (Updatable) Rule name. Must be unique within the module.
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        [Input("protectionCapabilities", required: true)]
        private InputList<Inputs.AppFirewallPolicyRequestProtectionRuleProtectionCapabilityGetArgs>? _protectionCapabilities;

        /// <summary>
        /// (Updatable) An ordered list that references OCI-managed protection capabilities. Referenced protection capabilities are not necessarily executed in order of appearance. Their execution order is decided at runtime for improved performance. The array cannot contain entries with the same pair of capability key and version more than once.
        /// </summary>
        public InputList<Inputs.AppFirewallPolicyRequestProtectionRuleProtectionCapabilityGetArgs> ProtectionCapabilities
        {
            get => _protectionCapabilities ?? (_protectionCapabilities = new InputList<Inputs.AppFirewallPolicyRequestProtectionRuleProtectionCapabilityGetArgs>());
            set => _protectionCapabilities = value;
        }

        /// <summary>
        /// (Updatable) Settings for protection capabilities
        /// </summary>
        [Input("protectionCapabilitySettings")]
        public Input<Inputs.AppFirewallPolicyRequestProtectionRuleProtectionCapabilitySettingsGetArgs>? ProtectionCapabilitySettings { get; set; }

        /// <summary>
        /// (Updatable) Type of WebAppFirewallPolicyRule.
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        public AppFirewallPolicyRequestProtectionRuleGetArgs()
        {
        }
        public static new AppFirewallPolicyRequestProtectionRuleGetArgs Empty => new AppFirewallPolicyRequestProtectionRuleGetArgs();
    }
}
