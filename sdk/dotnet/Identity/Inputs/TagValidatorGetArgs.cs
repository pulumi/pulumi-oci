// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class TagValidatorGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Specifies the type of validation: a static value (no validation) or a list.
        /// </summary>
        [Input("validatorType", required: true)]
        public Input<string> ValidatorType { get; set; } = null!;

        [Input("values", required: true)]
        private InputList<string>? _values;

        /// <summary>
        /// (Updatable) The list of allowed values for a definedTag value.
        /// </summary>
        public InputList<string> Values
        {
            get => _values ?? (_values = new InputList<string>());
            set => _values = value;
        }

        public TagValidatorGetArgs()
        {
        }
        public static new TagValidatorGetArgs Empty => new TagValidatorGetArgs();
    }
}
