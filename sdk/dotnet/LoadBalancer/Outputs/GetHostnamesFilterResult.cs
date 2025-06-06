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
    public sealed class GetHostnamesFilterResult
    {
        /// <summary>
        /// A friendly name for the hostname resource. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_hostname_001`
        /// </summary>
        public readonly string Name;
        public readonly bool? Regex;
        public readonly ImmutableArray<string> Values;

        [OutputConstructor]
        private GetHostnamesFilterResult(
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
