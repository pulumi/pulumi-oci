// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waf.Outputs
{

    [OutputType]
    public sealed class AppFirewallPolicyRequestAccessControl
    {
        /// <summary>
        /// (Updatable) References an default Action to take if no AccessControlRule was matched. Allowed action types:
        /// * **ALLOW** continues execution of other modules and their rules.
        /// * **RETURN_HTTP_RESPONSE** terminates further execution of modules and rules and returns defined HTTP response.
        /// </summary>
        public readonly string DefaultActionName;
        /// <summary>
        /// (Updatable) Ordered list of AccessControlRules. Rules are executed in order of appearance in this array.
        /// </summary>
        public readonly ImmutableArray<Outputs.AppFirewallPolicyRequestAccessControlRule> Rules;

        [OutputConstructor]
        private AppFirewallPolicyRequestAccessControl(
            string defaultActionName,

            ImmutableArray<Outputs.AppFirewallPolicyRequestAccessControlRule> rules)
        {
            DefaultActionName = defaultActionName;
            Rules = rules;
        }
    }
}
