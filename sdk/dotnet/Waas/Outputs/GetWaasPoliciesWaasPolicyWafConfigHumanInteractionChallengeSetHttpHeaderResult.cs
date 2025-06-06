// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Outputs
{

    [OutputType]
    public sealed class GetWaasPoliciesWaasPolicyWafConfigHumanInteractionChallengeSetHttpHeaderResult
    {
        /// <summary>
        /// The unique name of the whitelist.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The value of the header.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetWaasPoliciesWaasPolicyWafConfigHumanInteractionChallengeSetHttpHeaderResult(
            string name,

            string value)
        {
            Name = name;
            Value = value;
        }
    }
}
