// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class GetDomainsUserAttributesSettingAttributeSettingResult
    {
        /// <summary>
        /// End User mutability
        /// </summary>
        public readonly string EndUserMutability;
        /// <summary>
        /// Specifies the list of User mutabilities allowed.
        /// </summary>
        public readonly ImmutableArray<string> EndUserMutabilityCanonicalValues;
        /// <summary>
        /// Fully-qualified attribute or complex mapping Name
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private GetDomainsUserAttributesSettingAttributeSettingResult(
            string endUserMutability,

            ImmutableArray<string> endUserMutabilityCanonicalValues,

            string name)
        {
            EndUserMutability = endUserMutability;
            EndUserMutabilityCanonicalValues = endUserMutabilityCanonicalValues;
            Name = name;
        }
    }
}
