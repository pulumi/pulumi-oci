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
    public sealed class GetDeployArtifactDeployArtifactSourceResult
    {
        /// <summary>
        /// Specifies content for the inline artifact.
        /// </summary>
        public readonly string Base64encodedContent;
        /// <summary>
        /// The URL of an OCIR repository.
        /// </summary>
        public readonly string ChartUrl;
        /// <summary>
        /// Specifies the artifact path in the repository.
        /// </summary>
        public readonly string DeployArtifactPath;
        /// <summary>
        /// Specifies types of artifact sources.
        /// </summary>
        public readonly string DeployArtifactSourceType;
        /// <summary>
        /// Users can set this as a placeholder value that refers to a pipeline parameter, for example, ${appVersion}.
        /// </summary>
        public readonly string DeployArtifactVersion;
        /// <summary>
        /// Specifies image digest for the version of the image.
        /// </summary>
        public readonly string ImageDigest;
        /// <summary>
        /// Specifies OCIR Image Path - optionally include tag.
        /// </summary>
        public readonly string ImageUri;
        /// <summary>
        /// The OCID of a repository
        /// </summary>
        public readonly string RepositoryId;

        [OutputConstructor]
        private GetDeployArtifactDeployArtifactSourceResult(
            string base64encodedContent,

            string chartUrl,

            string deployArtifactPath,

            string deployArtifactSourceType,

            string deployArtifactVersion,

            string imageDigest,

            string imageUri,

            string repositoryId)
        {
            Base64encodedContent = base64encodedContent;
            ChartUrl = chartUrl;
            DeployArtifactPath = deployArtifactPath;
            DeployArtifactSourceType = deployArtifactSourceType;
            DeployArtifactVersion = deployArtifactVersion;
            ImageDigest = imageDigest;
            ImageUri = imageUri;
            RepositoryId = repositoryId;
        }
    }
}