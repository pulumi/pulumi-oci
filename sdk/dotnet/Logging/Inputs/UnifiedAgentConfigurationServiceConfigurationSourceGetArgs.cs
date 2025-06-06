// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Logging.Inputs
{

    public sealed class UnifiedAgentConfigurationServiceConfigurationSourceGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Advanced options for logging configuration
        /// </summary>
        [Input("advancedOptions")]
        public Input<Inputs.UnifiedAgentConfigurationServiceConfigurationSourceAdvancedOptionsGetArgs>? AdvancedOptions { get; set; }

        [Input("channels")]
        private InputList<string>? _channels;

        /// <summary>
        /// (Updatable) Windows event log channels.
        /// </summary>
        public InputList<string> Channels
        {
            get => _channels ?? (_channels = new InputList<string>());
            set => _channels = value;
        }

        /// <summary>
        /// (Updatable) User customized source plugin.
        /// </summary>
        [Input("customPlugin")]
        public Input<string>? CustomPlugin { get; set; }

        /// <summary>
        /// (Updatable) Unique name for the source.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// (Updatable) Source parser object.
        /// </summary>
        [Input("parser")]
        public Input<Inputs.UnifiedAgentConfigurationServiceConfigurationSourceParserGetArgs>? Parser { get; set; }

        [Input("paths")]
        private InputList<string>? _paths;

        /// <summary>
        /// (Updatable) Absolute paths for log source files. Wildcards can be used.
        /// </summary>
        public InputList<string> Paths
        {
            get => _paths ?? (_paths = new InputList<string>());
            set => _paths = value;
        }

        /// <summary>
        /// (Updatable) Unified schema logging source type.
        /// </summary>
        [Input("sourceType", required: true)]
        public Input<string> SourceType { get; set; } = null!;

        public UnifiedAgentConfigurationServiceConfigurationSourceGetArgs()
        {
        }
        public static new UnifiedAgentConfigurationServiceConfigurationSourceGetArgs Empty => new UnifiedAgentConfigurationServiceConfigurationSourceGetArgs();
    }
}
