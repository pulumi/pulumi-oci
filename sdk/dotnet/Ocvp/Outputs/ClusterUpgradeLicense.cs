// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Ocvp.Outputs
{

    [OutputType]
    public sealed class ClusterUpgradeLicense
    {
        /// <summary>
        /// vSphere license key value.
        /// </summary>
        public readonly string? LicenseKey;
        /// <summary>
        /// vSphere license type.
        /// </summary>
        public readonly string? LicenseType;

        [OutputConstructor]
        private ClusterUpgradeLicense(
            string? licenseKey,

            string? licenseType)
        {
            LicenseKey = licenseKey;
            LicenseType = licenseType;
        }
    }
}
