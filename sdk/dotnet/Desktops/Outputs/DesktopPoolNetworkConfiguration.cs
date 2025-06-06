// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Desktops.Outputs
{

    [OutputType]
    public sealed class DesktopPoolNetworkConfiguration
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet in the customer VCN where the connectivity will be established.
        /// </summary>
        public readonly string SubnetId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the customer VCN.
        /// </summary>
        public readonly string VcnId;

        [OutputConstructor]
        private DesktopPoolNetworkConfiguration(
            string subnetId,

            string vcnId)
        {
            SubnetId = subnetId;
            VcnId = vcnId;
        }
    }
}
