// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ResourceScheduler.Outputs
{

    [OutputType]
    public sealed class GetScheduleResourceParameterResult
    {
        /// <summary>
        /// This is the parameter type on which the input parameter is defined
        /// </summary>
        public readonly string ParameterType;
        /// <summary>
        /// This is the HTTP request header value.
        /// </summary>
        public readonly ImmutableArray<string> Values;

        [OutputConstructor]
        private GetScheduleResourceParameterResult(
            string parameterType,

            ImmutableArray<string> values)
        {
            ParameterType = parameterType;
            Values = values;
        }
    }
}
