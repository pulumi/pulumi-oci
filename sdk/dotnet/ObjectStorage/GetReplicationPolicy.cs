// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ObjectStorage
{
    public static class GetReplicationPolicy
    {
        /// <summary>
        /// This data source provides details about a specific Replication Policy resource in Oracle Cloud Infrastructure Object Storage service.
        /// 
        /// Get the replication policy.
        /// 
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testReplicationPolicy = Oci.ObjectStorage.GetReplicationPolicy.Invoke(new()
        ///     {
        ///         Bucket = replicationPolicyBucket,
        ///         Namespace = replicationPolicyNamespace,
        ///         ReplicationId = testReplication.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetReplicationPolicyResult> InvokeAsync(GetReplicationPolicyArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetReplicationPolicyResult>("oci:ObjectStorage/getReplicationPolicy:getReplicationPolicy", args ?? new GetReplicationPolicyArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Replication Policy resource in Oracle Cloud Infrastructure Object Storage service.
        /// 
        /// Get the replication policy.
        /// 
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testReplicationPolicy = Oci.ObjectStorage.GetReplicationPolicy.Invoke(new()
        ///     {
        ///         Bucket = replicationPolicyBucket,
        ///         Namespace = replicationPolicyNamespace,
        ///         ReplicationId = testReplication.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetReplicationPolicyResult> Invoke(GetReplicationPolicyInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetReplicationPolicyResult>("oci:ObjectStorage/getReplicationPolicy:getReplicationPolicy", args ?? new GetReplicationPolicyInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Replication Policy resource in Oracle Cloud Infrastructure Object Storage service.
        /// 
        /// Get the replication policy.
        /// 
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testReplicationPolicy = Oci.ObjectStorage.GetReplicationPolicy.Invoke(new()
        ///     {
        ///         Bucket = replicationPolicyBucket,
        ///         Namespace = replicationPolicyNamespace,
        ///         ReplicationId = testReplication.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetReplicationPolicyResult> Invoke(GetReplicationPolicyInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetReplicationPolicyResult>("oci:ObjectStorage/getReplicationPolicy:getReplicationPolicy", args ?? new GetReplicationPolicyInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetReplicationPolicyArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        /// </summary>
        [Input("bucket", required: true)]
        public string Bucket { get; set; } = null!;

        /// <summary>
        /// The Object Storage namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public string Namespace { get; set; } = null!;

        /// <summary>
        /// The ID of the replication policy.
        /// </summary>
        [Input("replicationId", required: true)]
        public string ReplicationId { get; set; } = null!;

        public GetReplicationPolicyArgs()
        {
        }
        public static new GetReplicationPolicyArgs Empty => new GetReplicationPolicyArgs();
    }

    public sealed class GetReplicationPolicyInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        /// </summary>
        [Input("bucket", required: true)]
        public Input<string> Bucket { get; set; } = null!;

        /// <summary>
        /// The Object Storage namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public Input<string> Namespace { get; set; } = null!;

        /// <summary>
        /// The ID of the replication policy.
        /// </summary>
        [Input("replicationId", required: true)]
        public Input<string> ReplicationId { get; set; } = null!;

        public GetReplicationPolicyInvokeArgs()
        {
        }
        public static new GetReplicationPolicyInvokeArgs Empty => new GetReplicationPolicyInvokeArgs();
    }


    [OutputType]
    public sealed class GetReplicationPolicyResult
    {
        public readonly string Bucket;
        public readonly string DeleteObjectInDestinationBucket;
        /// <summary>
        /// The bucket to replicate to in the destination region. Replication policy creation does not automatically create a destination bucket. Create the destination bucket before creating the policy.
        /// </summary>
        public readonly string DestinationBucketName;
        /// <summary>
        /// The destination region to replicate to, for example "us-ashburn-1".
        /// </summary>
        public readonly string DestinationRegionName;
        /// <summary>
        /// The id of the replication policy.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The name of the policy.
        /// </summary>
        public readonly string Name;
        public readonly string Namespace;
        public readonly string ReplicationId;
        /// <summary>
        /// The replication status of the policy. If the status is CLIENT_ERROR, once the user fixes the issue described in the status message, the status will become ACTIVE.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// A human-readable description of the status.
        /// </summary>
        public readonly string StatusMessage;
        /// <summary>
        /// The date when the replication policy was created as per [RFC 3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Changes made to the source bucket before this time has been replicated.
        /// </summary>
        public readonly string TimeLastSync;

        [OutputConstructor]
        private GetReplicationPolicyResult(
            string bucket,

            string deleteObjectInDestinationBucket,

            string destinationBucketName,

            string destinationRegionName,

            string id,

            string name,

            string @namespace,

            string replicationId,

            string status,

            string statusMessage,

            string timeCreated,

            string timeLastSync)
        {
            Bucket = bucket;
            DeleteObjectInDestinationBucket = deleteObjectInDestinationBucket;
            DestinationBucketName = destinationBucketName;
            DestinationRegionName = destinationRegionName;
            Id = id;
            Name = name;
            Namespace = @namespace;
            ReplicationId = replicationId;
            Status = status;
            StatusMessage = statusMessage;
            TimeCreated = timeCreated;
            TimeLastSync = timeLastSync;
        }
    }
}
