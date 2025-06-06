// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FileStorage.Outputs
{

    [OutputType]
    public sealed class GetReplicationsReplicationLockResult
    {
        /// <summary>
        /// A message added by the creator of the lock. This is typically used to give an indication of why the resource is locked.
        /// </summary>
        public readonly string Message;
        /// <summary>
        /// The ID of the resource that is locking this resource. Indicates that deleting this resource will remove the lock.
        /// </summary>
        public readonly string RelatedResourceId;
        /// <summary>
        /// The date and time the replication was created in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2021-01-04T20:01:29.100Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Type of the lock.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetReplicationsReplicationLockResult(
            string message,

            string relatedResourceId,

            string timeCreated,

            string type)
        {
            Message = message;
            RelatedResourceId = relatedResourceId;
            TimeCreated = timeCreated;
            Type = type;
        }
    }
}
