// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Logging.Inputs
{

    public sealed class UnifiedAgentConfigurationServiceConfigurationApplicationConfigurationUnifiedAgentConfigurationFilterArgs : global::Pulumi.ResourceArgs
    {
        [Input("allowLists")]
        private InputList<string>? _allowLists;

        /// <summary>
        /// (Updatable) List of metrics regex to be allowed.
        /// </summary>
        public InputList<string> AllowLists
        {
            get => _allowLists ?? (_allowLists = new InputList<string>());
            set => _allowLists = value;
        }

        [Input("denyLists")]
        private InputList<string>? _denyLists;

        /// <summary>
        /// (Updatable) List of metrics regex to be denied.
        /// </summary>
        public InputList<string> DenyLists
        {
            get => _denyLists ?? (_denyLists = new InputList<string>());
            set => _denyLists = value;
        }

        /// <summary>
        /// (Updatable) Unified schema logging filter type.
        /// </summary>
        [Input("filterType")]
        public Input<string>? FilterType { get; set; }

        /// <summary>
        /// (Updatable) Unique name for the filter.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        public UnifiedAgentConfigurationServiceConfigurationApplicationConfigurationUnifiedAgentConfigurationFilterArgs()
        {
        }
        public static new UnifiedAgentConfigurationServiceConfigurationApplicationConfigurationUnifiedAgentConfigurationFilterArgs Empty => new UnifiedAgentConfigurationServiceConfigurationApplicationConfigurationUnifiedAgentConfigurationFilterArgs();
    }
}
