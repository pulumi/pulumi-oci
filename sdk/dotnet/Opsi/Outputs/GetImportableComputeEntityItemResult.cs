// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opsi.Outputs
{

    [OutputType]
    public sealed class GetImportableComputeEntityItemResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The [Display Name](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Display) of the Compute Instance
        /// </summary>
        public readonly string ComputeDisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Compute Instance
        /// </summary>
        public readonly string ComputeId;
        /// <summary>
        /// Source of the importable agent entity.
        /// </summary>
        public readonly string EntitySource;
        /// <summary>
        /// The host name. The host name is unique amongst the hosts managed by the same management agent.
        /// </summary>
        public readonly string HostName;
        /// <summary>
        /// Platform type. Supported platformType(s) for MACS-managed external host insight: [LINUX, SOLARIS, WINDOWS]. Supported platformType(s) for MACS-managed cloud host insight: [LINUX]. Supported platformType(s) for EM-managed external host insight: [LINUX, SOLARIS, SUNOS, ZLINUX, WINDOWS].
        /// </summary>
        public readonly string PlatformType;

        [OutputConstructor]
        private GetImportableComputeEntityItemResult(
            string compartmentId,

            string computeDisplayName,

            string computeId,

            string entitySource,

            string hostName,

            string platformType)
        {
            CompartmentId = compartmentId;
            ComputeDisplayName = computeDisplayName;
            ComputeId = computeId;
            EntitySource = entitySource;
            HostName = hostName;
            PlatformType = platformType;
        }
    }
}
