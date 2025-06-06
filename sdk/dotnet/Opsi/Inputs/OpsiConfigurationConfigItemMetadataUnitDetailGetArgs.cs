// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opsi.Inputs
{

    public sealed class OpsiConfigurationConfigItemMetadataUnitDetailGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) User-friendly display name for the OPSI configuration. The name does not have to be unique.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// Unit of configuration item.
        /// </summary>
        [Input("unit")]
        public Input<string>? Unit { get; set; }

        public OpsiConfigurationConfigItemMetadataUnitDetailGetArgs()
        {
        }
        public static new OpsiConfigurationConfigItemMetadataUnitDetailGetArgs Empty => new OpsiConfigurationConfigItemMetadataUnitDetailGetArgs();
    }
}
