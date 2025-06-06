// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GenerativeAi.Inputs
{

    public sealed class AgentDataSourceDataSourceConfigGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The type of the tool. The allowed values are:
        /// * `OCI_OBJECT_STORAGE`: The data source is Oracle Cloud Infrastructure Object Storage.
        /// </summary>
        [Input("dataSourceConfigType", required: true)]
        public Input<string> DataSourceConfigType { get; set; } = null!;

        [Input("objectStoragePrefixes", required: true)]
        private InputList<Inputs.AgentDataSourceDataSourceConfigObjectStoragePrefixGetArgs>? _objectStoragePrefixes;

        /// <summary>
        /// (Updatable) The locations of data items in Object Storage, can either be an object (File) or a prefix (folder).
        /// </summary>
        public InputList<Inputs.AgentDataSourceDataSourceConfigObjectStoragePrefixGetArgs> ObjectStoragePrefixes
        {
            get => _objectStoragePrefixes ?? (_objectStoragePrefixes = new InputList<Inputs.AgentDataSourceDataSourceConfigObjectStoragePrefixGetArgs>());
            set => _objectStoragePrefixes = value;
        }

        public AgentDataSourceDataSourceConfigGetArgs()
        {
        }
        public static new AgentDataSourceDataSourceConfigGetArgs Empty => new AgentDataSourceDataSourceConfigGetArgs();
    }
}
