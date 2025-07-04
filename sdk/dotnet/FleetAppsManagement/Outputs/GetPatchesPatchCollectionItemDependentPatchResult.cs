// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Outputs
{

    [OutputType]
    public sealed class GetPatchesPatchCollectionItemDependentPatchResult
    {
        /// <summary>
        /// Unique identifier or OCID for listing a single Patch by id. Either compartmentId or id must be provided.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetPatchesPatchCollectionItemDependentPatchResult(string id)
        {
            Id = id;
        }
    }
}
