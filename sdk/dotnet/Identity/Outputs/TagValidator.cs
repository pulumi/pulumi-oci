// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class TagValidator
    {
        /// <summary>
        /// (Updatable) Specifies the type of validation: a static value (no validation) or a list.
        /// </summary>
        public readonly string ValidatorType;
        /// <summary>
        /// (Updatable) The list of allowed values for a definedTag value.
        /// </summary>
        public readonly ImmutableArray<string> Values;

        [OutputConstructor]
        private TagValidator(
            string validatorType,

            ImmutableArray<string> values)
        {
            ValidatorType = validatorType;
            Values = values;
        }
    }
}
