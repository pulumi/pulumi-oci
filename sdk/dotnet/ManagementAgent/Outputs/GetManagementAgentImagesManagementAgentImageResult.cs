// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ManagementAgent.Outputs
{

    [OutputType]
    public sealed class GetManagementAgentImagesManagementAgentImageResult
    {
        /// <summary>
        /// Agent image content SHA256 Hash
        /// </summary>
        public readonly string Checksum;
        /// <summary>
        /// Agent image resource id
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Object storage URL for download
        /// </summary>
        public readonly string ObjectUrl;
        /// <summary>
        /// The installation package target architecture type
        /// </summary>
        public readonly string PackageArchitectureType;
        /// <summary>
        /// The installation package type
        /// </summary>
        public readonly string PackageType;
        /// <summary>
        /// Agent image platform display name
        /// </summary>
        public readonly string PlatformName;
        /// <summary>
        /// Agent image platform type
        /// </summary>
        public readonly string PlatformType;
        /// <summary>
        /// Agent image size in bytes
        /// </summary>
        public readonly double Size;
        /// <summary>
        /// Filter to return only Management Agents in the particular lifecycle state.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Agent image version
        /// </summary>
        public readonly string Version;

        [OutputConstructor]
        private GetManagementAgentImagesManagementAgentImageResult(
            string checksum,

            string id,

            string objectUrl,

            string packageArchitectureType,

            string packageType,

            string platformName,

            string platformType,

            double size,

            string state,

            string version)
        {
            Checksum = checksum;
            Id = id;
            ObjectUrl = objectUrl;
            PackageArchitectureType = packageArchitectureType;
            PackageType = packageType;
            PlatformName = platformName;
            PlatformType = platformType;
            Size = size;
            State = state;
            Version = version;
        }
    }
}