// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub.Outputs
{

    [OutputType]
    public sealed class GetWindowsUpdatesWindowsUpdateCollectionItemResult
    {
        /// <summary>
        /// Description of the update.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Indicates whether the update can be installed using the service.
        /// </summary>
        public readonly string Installable;
        /// <summary>
        /// List of requirements for installing the update on the managed instance.
        /// </summary>
        public readonly ImmutableArray<string> InstallationRequirements;
        /// <summary>
        /// Indicates whether a reboot is required to complete the installation of this update.
        /// </summary>
        public readonly bool IsRebootRequiredForInstallation;
        /// <summary>
        /// List of the Microsoft Knowledge Base Article Ids related to this Windows Update.
        /// </summary>
        public readonly ImmutableArray<string> KbArticleIds;
        /// <summary>
        /// A filter based on the unique identifier for the Windows update. Note that this is not an OCID, but is a unique identifier assigned by Microsoft.  Example: '6981d463-cd91-4a26-b7c4-ea4ded9183ed'
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// size of the package in bytes
        /// </summary>
        public readonly string SizeInBytes;
        /// <summary>
        /// Unique identifier for the Windows update. Note that this is not an OCID, but is a unique identifier assigned by Microsoft.  Example: '6981d463-cd91-4a26-b7c4-ea4ded9183ed'
        /// </summary>
        public readonly string UpdateId;
        /// <summary>
        /// The type of Windows update.
        /// </summary>
        public readonly string UpdateType;

        [OutputConstructor]
        private GetWindowsUpdatesWindowsUpdateCollectionItemResult(
            string description,

            string installable,

            ImmutableArray<string> installationRequirements,

            bool isRebootRequiredForInstallation,

            ImmutableArray<string> kbArticleIds,

            string name,

            string sizeInBytes,

            string updateId,

            string updateType)
        {
            Description = description;
            Installable = installable;
            InstallationRequirements = installationRequirements;
            IsRebootRequiredForInstallation = isRebootRequiredForInstallation;
            KbArticleIds = kbArticleIds;
            Name = name;
            SizeInBytes = sizeInBytes;
            UpdateId = updateId;
            UpdateType = updateType;
        }
    }
}
