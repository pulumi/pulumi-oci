// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataIntegration.Outputs
{

    [OutputType]
    public sealed class WorkspaceApplicationPatchMetadataCountStatistic
    {
        /// <summary>
        /// The array of statistics.
        /// </summary>
        public readonly ImmutableArray<Outputs.WorkspaceApplicationPatchMetadataCountStatisticObjectTypeCountList> ObjectTypeCountLists;

        [OutputConstructor]
        private WorkspaceApplicationPatchMetadataCountStatistic(ImmutableArray<Outputs.WorkspaceApplicationPatchMetadataCountStatisticObjectTypeCountList> objectTypeCountLists)
        {
            ObjectTypeCountLists = objectTypeCountLists;
        }
    }
}
