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
    public sealed class GetAddressRuleContactFieldResult
    {
        /// <summary>
        /// Format information
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAddressRuleContactFieldFormatResult> Formats;
        /// <summary>
        /// The given field is requeired or not
        /// </summary>
        public readonly bool IsRequired;
        /// <summary>
        /// Label information
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAddressRuleContactFieldLabelResult> Labels;
        /// <summary>
        /// Locale code (rfc4646 format) of a forced language (e.g.: jp addresses require jp always)
        /// </summary>
        public readonly string Language;
        /// <summary>
        /// User friendly name
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private GetAddressRuleContactFieldResult(
            ImmutableArray<Outputs.GetAddressRuleContactFieldFormatResult> formats,

            bool isRequired,

            ImmutableArray<Outputs.GetAddressRuleContactFieldLabelResult> labels,

            string language,

            string name)
        {
            Formats = formats;
            IsRequired = isRequired;
            Labels = labels;
            Language = language;
            Name = name;
        }
    }
}
