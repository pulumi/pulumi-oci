// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waf.Inputs
{

    public sealed class AppFirewallPolicyRequestRateLimitingArgs : global::Pulumi.ResourceArgs
    {
        [Input("rules")]
        private InputList<Inputs.AppFirewallPolicyRequestRateLimitingRuleArgs>? _rules;

        /// <summary>
        /// (Updatable) Ordered list of RequestRateLimitingRules. Rules are executed in order of appearance in this array.
        /// </summary>
        public InputList<Inputs.AppFirewallPolicyRequestRateLimitingRuleArgs> Rules
        {
            get => _rules ?? (_rules = new InputList<Inputs.AppFirewallPolicyRequestRateLimitingRuleArgs>());
            set => _rules = value;
        }

        public AppFirewallPolicyRequestRateLimitingArgs()
        {
        }
        public static new AppFirewallPolicyRequestRateLimitingArgs Empty => new AppFirewallPolicyRequestRateLimitingArgs();
    }
}
