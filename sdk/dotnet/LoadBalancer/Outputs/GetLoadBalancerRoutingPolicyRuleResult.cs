// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer.Outputs
{

    [OutputType]
    public sealed class GetLoadBalancerRoutingPolicyRuleResult
    {
        /// <summary>
        /// A list of actions to be applied when conditions of the routing rule are met.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetLoadBalancerRoutingPolicyRuleActionResult> Actions;
        /// <summary>
        /// A routing rule to evaluate defined conditions against the incoming HTTP request and perform an action.
        /// </summary>
        public readonly string Condition;
        /// <summary>
        /// A unique name for the routing policy rule. Avoid entering confidential information.
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private GetLoadBalancerRoutingPolicyRuleResult(
            ImmutableArray<Outputs.GetLoadBalancerRoutingPolicyRuleActionResult> actions,

            string condition,

            string name)
        {
            Actions = actions;
            Condition = condition;
            Name = name;
        }
    }
}
