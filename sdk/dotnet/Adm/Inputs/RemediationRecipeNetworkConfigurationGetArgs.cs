// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Adm.Inputs
{

    public sealed class RemediationRecipeNetworkConfigurationGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("nsgIds")]
        private InputList<string>? _nsgIds;

        /// <summary>
        /// (Updatable) The list of Oracle Cloud Identifiers ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) corresponding to Network Security Groups.
        /// </summary>
        public InputList<string> NsgIds
        {
            get => _nsgIds ?? (_nsgIds = new InputList<string>());
            set => _nsgIds = value;
        }

        /// <summary>
        /// (Updatable) The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the subnet.
        /// </summary>
        [Input("subnetId", required: true)]
        public Input<string> SubnetId { get; set; } = null!;

        public RemediationRecipeNetworkConfigurationGetArgs()
        {
        }
        public static new RemediationRecipeNetworkConfigurationGetArgs Empty => new RemediationRecipeNetworkConfigurationGetArgs();
    }
}
