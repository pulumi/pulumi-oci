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
    public sealed class GetDeployStagesDeployStageCollectionItemSetStringResult
    {
        /// <summary>
        /// List of parameters defined to set helm value.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeployStagesDeployStageCollectionItemSetStringItemResult> Items;

        [OutputConstructor]
        private GetDeployStagesDeployStageCollectionItemSetStringResult(ImmutableArray<Outputs.GetDeployStagesDeployStageCollectionItemSetStringItemResult> items)
        {
            Items = items;
        }
    }
}
