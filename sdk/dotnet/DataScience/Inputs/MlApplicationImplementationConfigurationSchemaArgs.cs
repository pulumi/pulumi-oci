// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Inputs
{

    public sealed class MlApplicationImplementationConfigurationSchemaArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The default value for the optional configuration property (it must not be specified for mandatory configuration properties)
        /// </summary>
        [Input("defaultValue")]
        public Input<string>? DefaultValue { get; set; }

        /// <summary>
        /// short description of the argument
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// argument is mandatory or not
        /// </summary>
        [Input("isMandatory")]
        public Input<bool>? IsMandatory { get; set; }

        /// <summary>
        /// Name of key (parameter name)
        /// </summary>
        [Input("keyName")]
        public Input<string>? KeyName { get; set; }

        /// <summary>
        /// Sample property value (it must match validationRegexp if it is specified)
        /// </summary>
        [Input("sampleValue")]
        public Input<string>? SampleValue { get; set; }

        /// <summary>
        /// A regular expression will be used for the validation of property value.
        /// </summary>
        [Input("validationRegexp")]
        public Input<string>? ValidationRegexp { get; set; }

        /// <summary>
        /// Type of value
        /// </summary>
        [Input("valueType")]
        public Input<string>? ValueType { get; set; }

        public MlApplicationImplementationConfigurationSchemaArgs()
        {
        }
        public static new MlApplicationImplementationConfigurationSchemaArgs Empty => new MlApplicationImplementationConfigurationSchemaArgs();
    }
}
