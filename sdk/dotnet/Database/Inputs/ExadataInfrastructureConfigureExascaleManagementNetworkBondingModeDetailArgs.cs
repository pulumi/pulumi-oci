// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class ExadataInfrastructureConfigureExascaleManagementNetworkBondingModeDetailArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The network bonding mode for the Exadata infrastructure.
        /// </summary>
        [Input("backupNetworkBondingMode")]
        public Input<string>? BackupNetworkBondingMode { get; set; }

        /// <summary>
        /// The network bonding mode for the Exadata infrastructure.
        /// </summary>
        [Input("clientNetworkBondingMode")]
        public Input<string>? ClientNetworkBondingMode { get; set; }

        /// <summary>
        /// The network bonding mode for the Exadata infrastructure.
        /// </summary>
        [Input("drNetworkBondingMode")]
        public Input<string>? DrNetworkBondingMode { get; set; }

        public ExadataInfrastructureConfigureExascaleManagementNetworkBondingModeDetailArgs()
        {
        }
        public static new ExadataInfrastructureConfigureExascaleManagementNetworkBondingModeDetailArgs Empty => new ExadataInfrastructureConfigureExascaleManagementNetworkBondingModeDetailArgs();
    }
}
