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
    public sealed class GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemActionResult
    {
        /// <summary>
        /// Type of returned HTTP response body.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemActionBodyResult> Bodies;
        /// <summary>
        /// Response code.
        /// </summary>
        public readonly int Code;
        /// <summary>
        /// Adds headers defined in this array for HTTP response.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemActionHeaderResult> Headers;
        /// <summary>
        /// Rule name. Must be unique within the module.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Type of WebAppFirewallPolicyRule.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemActionResult(
            ImmutableArray<Outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemActionBodyResult> bodies,

            int code,

            ImmutableArray<Outputs.GetWebAppFirewallPoliciesWebAppFirewallPolicyCollectionItemActionHeaderResult> headers,

            string name,

            string type)
        {
            Bodies = bodies;
            Code = code;
            Headers = headers;
            Name = name;
            Type = type;
        }
    }
}