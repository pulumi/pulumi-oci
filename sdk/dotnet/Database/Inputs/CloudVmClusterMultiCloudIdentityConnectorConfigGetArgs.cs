// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class CloudVmClusterMultiCloudIdentityConnectorConfigGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Cloud provider
        /// </summary>
        [Input("cloudProvider")]
        public Input<string>? CloudProvider { get; set; }

        /// <summary>
        /// The OCID of the identity connector
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        public CloudVmClusterMultiCloudIdentityConnectorConfigGetArgs()
        {
        }
        public static new CloudVmClusterMultiCloudIdentityConnectorConfigGetArgs Empty => new CloudVmClusterMultiCloudIdentityConnectorConfigGetArgs();
    }
}
