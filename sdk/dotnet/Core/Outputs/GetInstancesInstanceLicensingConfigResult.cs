// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetInstancesInstanceLicensingConfigResult
    {
        /// <summary>
        /// License Type for the OS license.
        /// * `OCI_PROVIDED` - Oracle Cloud Infrastructure provided license (e.g. metered $/OCPU-hour).
        /// * `BRING_YOUR_OWN_LICENSE` - Bring your own license.
        /// </summary>
        public readonly string LicenseType;
        /// <summary>
        /// The Operating System version of the license config.
        /// </summary>
        public readonly string OsVersion;
        /// <summary>
        /// (Required) The type of action to run when the instance is interrupted for eviction.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetInstancesInstanceLicensingConfigResult(
            string licenseType,

            string osVersion,

            string type)
        {
            LicenseType = licenseType;
            OsVersion = osVersion;
            Type = type;
        }
    }
}
