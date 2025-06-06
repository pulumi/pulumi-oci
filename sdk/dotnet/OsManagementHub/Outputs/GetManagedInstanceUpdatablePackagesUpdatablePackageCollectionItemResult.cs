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
    public sealed class GetManagedInstanceUpdatablePackagesUpdatablePackageCollectionItemResult
    {
        /// <summary>
        /// The architecture for which this package was built.
        /// </summary>
        public readonly string Architecture;
        /// <summary>
        /// A filter to return resources that match the given display names.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// List of errata applicable to this update.
        /// </summary>
        public readonly ImmutableArray<string> Erratas;
        /// <summary>
        /// The version of the package that is currently installed on the instance.
        /// </summary>
        public readonly string InstalledVersion;
        /// <summary>
        /// Unique identifier for the package.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Status of the software package.
        /// </summary>
        public readonly string PackageClassification;
        /// <summary>
        /// List of CVEs applicable to this erratum.
        /// </summary>
        public readonly ImmutableArray<string> RelatedCves;
        /// <summary>
        /// List of software sources that provide the software package.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedInstanceUpdatablePackagesUpdatablePackageCollectionItemSoftwareSourceResult> SoftwareSources;
        /// <summary>
        /// Type of the package.
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// The type of update.
        /// </summary>
        public readonly string UpdateType;
        /// <summary>
        /// Version of the installed package.
        /// </summary>
        public readonly string Version;

        [OutputConstructor]
        private GetManagedInstanceUpdatablePackagesUpdatablePackageCollectionItemResult(
            string architecture,

            string displayName,

            ImmutableArray<string> erratas,

            string installedVersion,

            string name,

            string packageClassification,

            ImmutableArray<string> relatedCves,

            ImmutableArray<Outputs.GetManagedInstanceUpdatablePackagesUpdatablePackageCollectionItemSoftwareSourceResult> softwareSources,

            string type,

            string updateType,

            string version)
        {
            Architecture = architecture;
            DisplayName = displayName;
            Erratas = erratas;
            InstalledVersion = installedVersion;
            Name = name;
            PackageClassification = packageClassification;
            RelatedCves = relatedCves;
            SoftwareSources = softwareSources;
            Type = type;
            UpdateType = updateType;
            Version = version;
        }
    }
}
