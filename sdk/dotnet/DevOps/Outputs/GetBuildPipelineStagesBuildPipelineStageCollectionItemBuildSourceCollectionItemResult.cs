// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Outputs
{

    [OutputType]
    public sealed class GetBuildPipelineStagesBuildPipelineStageCollectionItemBuildSourceCollectionItemResult
    {
        /// <summary>
        /// Branch name.
        /// </summary>
        public readonly string Branch;
        /// <summary>
        /// Connection identifier pertinent to Bitbucket Server source provider
        /// </summary>
        public readonly string ConnectionId;
        /// <summary>
        /// The type of source provider.
        /// </summary>
        public readonly string ConnectionType;
        /// <summary>
        /// Name of the build source. This must be unique within a build source collection. The name can be used by customers to locate the working directory pertinent to this repository.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The DevOps code repository ID.
        /// </summary>
        public readonly string RepositoryId;
        /// <summary>
        /// URL for the repository.
        /// </summary>
        public readonly string RepositoryUrl;

        [OutputConstructor]
        private GetBuildPipelineStagesBuildPipelineStageCollectionItemBuildSourceCollectionItemResult(
            string branch,

            string connectionId,

            string connectionType,

            string name,

            string repositoryId,

            string repositoryUrl)
        {
            Branch = branch;
            ConnectionId = connectionId;
            ConnectionType = connectionType;
            Name = name;
            RepositoryId = repositoryId;
            RepositoryUrl = repositoryUrl;
        }
    }
}