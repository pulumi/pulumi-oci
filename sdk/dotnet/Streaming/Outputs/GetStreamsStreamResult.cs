// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Streaming.Outputs
{

    [OutputType]
    public sealed class GetStreamsStreamResult
    {
        /// <summary>
        /// The OCID of the compartment. Is exclusive with the `streamPoolId` parameter. One of them is required.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations": {"CostCenter": "42"}}'
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// A filter to return only resources that match the given ID exactly.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Any additional details about the current state of the stream.
        /// </summary>
        public readonly string LifecycleStateDetails;
        /// <summary>
        /// The endpoint to use when creating the StreamClient to consume or publish messages in the stream. If the associated stream pool is private, the endpoint is also private and can only be accessed from inside the stream pool's associated subnet.
        /// </summary>
        public readonly string MessagesEndpoint;
        /// <summary>
        /// A filter to return only resources that match the given name exactly.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The number of partitions in the stream.
        /// </summary>
        public readonly int Partitions;
        /// <summary>
        /// The retention period of the stream, in hours. This property is read-only.
        /// </summary>
        public readonly int RetentionInHours;
        /// <summary>
        /// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The OCID of the stream pool. Is exclusive with the `compartmentId` parameter. One of them is required.
        /// </summary>
        public readonly string StreamPoolId;
        /// <summary>
        /// The date and time the stream was created, expressed in in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2018-04-20T00:00:07.405Z`
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetStreamsStreamResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleStateDetails,

            string messagesEndpoint,

            string name,

            int partitions,

            int retentionInHours,

            string state,

            string streamPoolId,

            string timeCreated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleStateDetails = lifecycleStateDetails;
            MessagesEndpoint = messagesEndpoint;
            Name = name;
            Partitions = partitions;
            RetentionInHours = retentionInHours;
            State = state;
            StreamPoolId = streamPoolId;
            TimeCreated = timeCreated;
        }
    }
}
