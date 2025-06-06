// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Optimizer.Outputs
{

    [OutputType]
    public sealed class GetProfileTargetTagResult
    {
        /// <summary>
        /// The list of tags specified in the current profile override.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetProfileTargetTagItemResult> Items;

        [OutputConstructor]
        private GetProfileTargetTagResult(ImmutableArray<Outputs.GetProfileTargetTagItemResult> items)
        {
            Items = items;
        }
    }
}
