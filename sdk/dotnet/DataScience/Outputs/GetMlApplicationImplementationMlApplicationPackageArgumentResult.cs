// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Outputs
{

    [OutputType]
    public sealed class GetMlApplicationImplementationMlApplicationPackageArgumentResult
    {
        /// <summary>
        /// Array of the ML Application package arguments
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMlApplicationImplementationMlApplicationPackageArgumentArgumentResult> Arguments;

        [OutputConstructor]
        private GetMlApplicationImplementationMlApplicationPackageArgumentResult(ImmutableArray<Outputs.GetMlApplicationImplementationMlApplicationPackageArgumentArgumentResult> arguments)
        {
            Arguments = arguments;
        }
    }
}
