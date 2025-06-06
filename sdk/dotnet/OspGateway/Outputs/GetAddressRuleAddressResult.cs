// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OspGateway.Outputs
{

    [OutputType]
    public sealed class GetAddressRuleAddressResult
    {
        /// <summary>
        /// Tax type rule fields
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAddressRuleAddressFieldResult> Fields;
        /// <summary>
        /// Third party validation.
        /// </summary>
        public readonly string ThirdPartyValidation;

        [OutputConstructor]
        private GetAddressRuleAddressResult(
            ImmutableArray<Outputs.GetAddressRuleAddressFieldResult> fields,

            string thirdPartyValidation)
        {
            Fields = fields;
            ThirdPartyValidation = thirdPartyValidation;
        }
    }
}
