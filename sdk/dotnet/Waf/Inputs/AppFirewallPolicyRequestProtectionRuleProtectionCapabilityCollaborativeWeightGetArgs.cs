// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waf.Inputs
{

    public sealed class AppFirewallPolicyRequestProtectionRuleProtectionCapabilityCollaborativeWeightGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Unique key of collaborative capability for which weight will be overridden.
        /// </summary>
        [Input("key", required: true)]
        public Input<string> Key { get; set; } = null!;

        /// <summary>
        /// (Updatable) The value of weight to set.
        /// </summary>
        [Input("weight", required: true)]
        public Input<int> Weight { get; set; } = null!;

        public AppFirewallPolicyRequestProtectionRuleProtectionCapabilityCollaborativeWeightGetArgs()
        {
        }
        public static new AppFirewallPolicyRequestProtectionRuleProtectionCapabilityCollaborativeWeightGetArgs Empty => new AppFirewallPolicyRequestProtectionRuleProtectionCapabilityCollaborativeWeightGetArgs();
    }
}
