// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Outputs
{

    [OutputType]
    public sealed class GetWaasPoliciesWaasPolicyOriginGroupResult
    {
        public readonly string Label;
        public readonly ImmutableArray<Outputs.GetWaasPoliciesWaasPolicyOriginGroupOriginGroupResult> OriginGroups;

        [OutputConstructor]
        private GetWaasPoliciesWaasPolicyOriginGroupResult(
            string label,

            ImmutableArray<Outputs.GetWaasPoliciesWaasPolicyOriginGroupOriginGroupResult> originGroups)
        {
            Label = label;
            OriginGroups = originGroups;
        }
    }
}