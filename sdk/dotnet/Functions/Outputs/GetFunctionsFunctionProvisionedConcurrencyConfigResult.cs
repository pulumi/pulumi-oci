// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Functions.Outputs
{

    [OutputType]
    public sealed class GetFunctionsFunctionProvisionedConcurrencyConfigResult
    {
        public readonly int Count;
        /// <summary>
        /// The strategy for provisioned concurrency to be used.
        /// </summary>
        public readonly string Strategy;

        [OutputConstructor]
        private GetFunctionsFunctionProvisionedConcurrencyConfigResult(
            int count,

            string strategy)
        {
            Count = count;
            Strategy = strategy;
        }
    }
}