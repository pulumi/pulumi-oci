// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ServiceCatalog.Outputs
{

    [OutputType]
    public sealed class PrivateApplicationPackageDetails
    {
        /// <summary>
        /// The package's type.
        /// </summary>
        public readonly string PackageType;
        /// <summary>
        /// The package version.
        /// </summary>
        public readonly string Version;
        public readonly string? ZipFileBase64encoded;

        [OutputConstructor]
        private PrivateApplicationPackageDetails(
            string packageType,

            string version,

            string? zipFileBase64encoded)
        {
            PackageType = packageType;
            Version = version;
            ZipFileBase64encoded = zipFileBase64encoded;
        }
    }
}
