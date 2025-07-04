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
    public sealed class GetComputeHostGroupConfigurationResult
    {
        /// <summary>
        /// The OCID for firmware bundle
        /// </summary>
        public readonly string FirmwareBundleId;
        /// <summary>
        /// Preferred recycle level for hosts associated with the reservation config.
        /// * `SKIP_RECYCLE` - Skips host wipe.
        /// * `FULL_RECYCLE` - Does not skip host wipe. This is the default behavior.
        /// </summary>
        public readonly string RecycleLevel;
        /// <summary>
        /// Either the platform name or compute shape that the configuration is targeting
        /// </summary>
        public readonly string Target;

        [OutputConstructor]
        private GetComputeHostGroupConfigurationResult(
            string firmwareBundleId,

            string recycleLevel,

            string target)
        {
            FirmwareBundleId = firmwareBundleId;
            RecycleLevel = recycleLevel;
            Target = target;
        }
    }
}
