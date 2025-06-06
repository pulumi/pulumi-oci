// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.BigDataService.Outputs
{

    [OutputType]
    public sealed class GetAutoScalingConfigurationsAutoScalingConfigurationPolicyResult
    {
        public readonly string PolicyType;
        public readonly ImmutableArray<Outputs.GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRuleResult> Rules;

        [OutputConstructor]
        private GetAutoScalingConfigurationsAutoScalingConfigurationPolicyResult(
            string policyType,

            ImmutableArray<Outputs.GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRuleResult> rules)
        {
            PolicyType = policyType;
            Rules = rules;
        }
    }
}
