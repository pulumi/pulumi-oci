// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer.Outputs
{

    [OutputType]
    public sealed class GetSslCipherSuitesFilterResult
    {
        /// <summary>
        /// A friendly name for the SSL cipher suite. It must be unique and it cannot be changed.
        /// </summary>
        public readonly string Name;
        public readonly bool? Regex;
        public readonly ImmutableArray<string> Values;

        [OutputConstructor]
        private GetSslCipherSuitesFilterResult(
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