// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GoldenGate.Outputs
{

    [OutputType]
    public sealed class GetConnectionAdditionalAttributeResult
    {
        /// <summary>
        /// The name of the property entry.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The value of the property entry.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetConnectionAdditionalAttributeResult(
            string name,

            string value)
        {
            Name = name;
            Value = value;
        }
    }
}