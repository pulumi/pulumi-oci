// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.MediaServices.Outputs
{

    [OutputType]
    public sealed class GetMediaWorkflowJobsMediaWorkflowJobCollectionItemOutputResult
    {
        /// <summary>
        /// Type of job output.
        /// </summary>
        public readonly string AssetType;
        /// <summary>
        /// The bucket name of the job output.
        /// </summary>
        public readonly string Bucket;
        /// <summary>
        /// unique MediaWorkflowJob identifier
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The namespace name of the job output.
        /// </summary>
        public readonly string Namespace;
        /// <summary>
        /// The object name of the job output.
        /// </summary>
        public readonly string Object;

        [OutputConstructor]
        private GetMediaWorkflowJobsMediaWorkflowJobCollectionItemOutputResult(
            string assetType,

            string bucket,

            string id,

            string @namespace,

            string @object)
        {
            AssetType = assetType;
            Bucket = bucket;
            Id = id;
            Namespace = @namespace;
            Object = @object;
        }
    }
}
