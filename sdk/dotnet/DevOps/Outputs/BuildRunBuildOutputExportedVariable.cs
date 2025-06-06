// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Outputs
{

    [OutputType]
    public sealed class BuildRunBuildOutputExportedVariable
    {
        /// <summary>
        /// List of exported variables.
        /// </summary>
        public readonly ImmutableArray<Outputs.BuildRunBuildOutputExportedVariableItem> Items;

        [OutputConstructor]
        private BuildRunBuildOutputExportedVariable(ImmutableArray<Outputs.BuildRunBuildOutputExportedVariableItem> items)
        {
            Items = items;
        }
    }
}
