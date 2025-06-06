// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Inputs
{

    public sealed class MlApplicationInstanceConfigurationGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Key of configuration property
        /// </summary>
        [Input("key", required: true)]
        public Input<string> Key { get; set; } = null!;

        /// <summary>
        /// (Updatable) Value of configuration property
        /// </summary>
        [Input("value")]
        public Input<string>? Value { get; set; }

        public MlApplicationInstanceConfigurationGetArgs()
        {
        }
        public static new MlApplicationInstanceConfigurationGetArgs Empty => new MlApplicationInstanceConfigurationGetArgs();
    }
}
