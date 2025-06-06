// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiLanguage.Inputs
{

    public sealed class ModelModelDetailsClassificationModeGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// classification Modes
        /// </summary>
        [Input("classificationMode", required: true)]
        public Input<string> ClassificationMode { get; set; } = null!;

        /// <summary>
        /// Optional if nothing specified latest base model will be used for training. Supported versions can be found at /modelTypes/{modelType}
        /// </summary>
        [Input("version")]
        public Input<string>? Version { get; set; }

        public ModelModelDetailsClassificationModeGetArgs()
        {
        }
        public static new ModelModelDetailsClassificationModeGetArgs Empty => new ModelModelDetailsClassificationModeGetArgs();
    }
}
