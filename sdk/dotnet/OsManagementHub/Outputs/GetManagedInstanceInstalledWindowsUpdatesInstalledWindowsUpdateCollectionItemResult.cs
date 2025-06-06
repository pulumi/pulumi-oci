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
    public sealed class GetManagedInstanceInstalledWindowsUpdatesInstalledWindowsUpdateCollectionItemResult
    {
        /// <summary>
        /// A filter based on the unique identifier for the Windows update. Note that this is not an OCID, but is a unique identifier assigned by Microsoft.  Example: '6981d463-cd91-4a26-b7c4-ea4ded9183ed'
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Unique identifier for the Windows update. Note that this is not an OCID, but is a unique identifier assigned by Microsoft.  Example: '6981d463-cd91-4a26-b7c4-ea4ded9183ed'
        /// </summary>
        public readonly string UpdateId;
        /// <summary>
        /// The type of Windows update.
        /// </summary>
        public readonly string UpdateType;

        [OutputConstructor]
        private GetManagedInstanceInstalledWindowsUpdatesInstalledWindowsUpdateCollectionItemResult(
            string name,

            string updateId,

            string updateType)
        {
            Name = name;
            UpdateId = updateId;
            UpdateType = updateType;
        }
    }
}
