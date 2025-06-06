// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Jms.Inputs
{

    public sealed class FleetAdvancedFeatureConfigurationJfrRecordingArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) JfrRecording flag to store enabled or disabled status.
        /// </summary>
        [Input("isEnabled")]
        public Input<bool>? IsEnabled { get; set; }

        public FleetAdvancedFeatureConfigurationJfrRecordingArgs()
        {
        }
        public static new FleetAdvancedFeatureConfigurationJfrRecordingArgs Empty => new FleetAdvancedFeatureConfigurationJfrRecordingArgs();
    }
}
