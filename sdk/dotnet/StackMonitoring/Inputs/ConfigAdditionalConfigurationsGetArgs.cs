// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring.Inputs
{

    public sealed class ConfigAdditionalConfigurationsGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("propertiesMap")]
        private InputMap<string>? _propertiesMap;

        /// <summary>
        /// (Updatable) Key/Value pair of Property
        /// </summary>
        public InputMap<string> PropertiesMap
        {
            get => _propertiesMap ?? (_propertiesMap = new InputMap<string>());
            set => _propertiesMap = value;
        }

        public ConfigAdditionalConfigurationsGetArgs()
        {
        }
        public static new ConfigAdditionalConfigurationsGetArgs Empty => new ConfigAdditionalConfigurationsGetArgs();
    }
}
