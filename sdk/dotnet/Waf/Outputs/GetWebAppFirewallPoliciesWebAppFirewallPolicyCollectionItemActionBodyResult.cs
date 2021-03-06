// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waf.Outputs
{

    [OutputType]
    public sealed class GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemActionBodyResult
    {
        /// <summary>
        /// Static response body text.
        /// </summary>
        public readonly string Text;
        /// <summary>
        /// Type of WebAppFirewallPolicyRule.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemActionBodyResult(
            string text,

            string type)
        {
            Text = text;
            Type = type;
        }
    }
}
