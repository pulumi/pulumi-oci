// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkFirewall.Outputs
{

    [OutputType]
    public sealed class NetworkFirewallPolicyDecryptionRulePosition
    {
        /// <summary>
        /// (Updatable) Identifier for rule after which this rule lies.
        /// </summary>
        public readonly string? AfterRule;
        /// <summary>
        /// (Updatable) Identifier for rule before which this rule lies.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public readonly string? BeforeRule;

        [OutputConstructor]
        private NetworkFirewallPolicyDecryptionRulePosition(
            string? afterRule,

            string? beforeRule)
        {
            AfterRule = afterRule;
            BeforeRule = beforeRule;
        }
    }
}
