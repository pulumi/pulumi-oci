// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.RecoveryMod.Outputs
{

    [OutputType]
    public sealed class GetProtectionPoliciesProtectionPolicyCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetProtectionPoliciesProtectionPolicyCollectionItemResult> Items;

        [OutputConstructor]
        private GetProtectionPoliciesProtectionPolicyCollectionResult(ImmutableArray<Outputs.GetProtectionPoliciesProtectionPolicyCollectionItemResult> items)
        {
            Items = items;
        }
    }
}