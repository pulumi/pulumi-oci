// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GoldenGate.Outputs
{

    [OutputType]
    public sealed class GetTrailFilesTrailFileCollectionItemResult
    {
        /// <summary>
        /// array of consumer process names
        /// </summary>
        public readonly ImmutableArray<string> Consumers;
        /// <summary>
        /// A filter to return only the resources that match the entire 'displayName' given.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Maximum sequence number
        /// </summary>
        public readonly string MaxSequenceNumber;
        /// <summary>
        /// Minimum sequence number
        /// </summary>
        public readonly string MinSequenceNumber;
        /// <summary>
        /// Number of sequences for a specific trail file
        /// </summary>
        public readonly int NumberOfSequences;
        /// <summary>
        /// Producer Process Name if any.
        /// </summary>
        public readonly string Producer;
        /// <summary>
        /// The size of the backup stored in object storage (in bytes)
        /// </summary>
        public readonly double SizeInBytes;
        /// <summary>
        /// The time the resource was last updated. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        /// </summary>
        public readonly string TimeLastUpdated;
        /// <summary>
        /// A Trail File identifier
        /// </summary>
        public readonly string TrailFileId;

        [OutputConstructor]
        private GetTrailFilesTrailFileCollectionItemResult(
            ImmutableArray<string> consumers,

            string displayName,

            string maxSequenceNumber,

            string minSequenceNumber,

            int numberOfSequences,

            string producer,

            double sizeInBytes,

            string timeLastUpdated,

            string trailFileId)
        {
            Consumers = consumers;
            DisplayName = displayName;
            MaxSequenceNumber = maxSequenceNumber;
            MinSequenceNumber = minSequenceNumber;
            NumberOfSequences = numberOfSequences;
            Producer = producer;
            SizeInBytes = sizeInBytes;
            TimeLastUpdated = timeLastUpdated;
            TrailFileId = trailFileId;
        }
    }
}
