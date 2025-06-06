// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Outputs
{

    [OutputType]
    public sealed class GetDeployStageSetValueItemResult
    {
        /// <summary>
        /// Name of the parameter (case-sensitive).
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Value of the parameter.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetDeployStageSetValueItemResult(
            string name,

            string value)
        {
            Name = name;
            Value = value;
        }
    }
}
