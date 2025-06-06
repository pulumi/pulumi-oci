// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Ocvp.Outputs
{

    [OutputType]
    public sealed class SddcDatastore
    {
        /// <summary>
        /// A list of [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)s of Block Storage Volumes.
        /// </summary>
        public readonly ImmutableArray<string> BlockVolumeIds;
        /// <summary>
        /// Size of the Block Storage Volume in GB.
        /// </summary>
        public readonly double? Capacity;
        /// <summary>
        /// Type of the datastore.
        /// </summary>
        public readonly string DatastoreType;

        [OutputConstructor]
        private SddcDatastore(
            ImmutableArray<string> blockVolumeIds,

            double? capacity,

            string datastoreType)
        {
            BlockVolumeIds = blockVolumeIds;
            Capacity = capacity;
            DatastoreType = datastoreType;
        }
    }
}
