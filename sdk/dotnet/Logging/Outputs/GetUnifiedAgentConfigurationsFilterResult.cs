// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Logging.Outputs
{

    [OutputType]
    public sealed class GetUnifiedAgentConfigurationsFilterResult
    {
        /// <summary>
        /// The name key to tag this Grok pattern.
        /// </summary>
        public readonly string Name;
        public readonly bool? Regex;
        public readonly ImmutableArray<string> Values;

        [OutputConstructor]
        private GetUnifiedAgentConfigurationsFilterResult(
            string name,

            bool? regex,

            ImmutableArray<string> values)
        {
            Name = name;
            Regex = regex;
            Values = values;
        }
    }
}
