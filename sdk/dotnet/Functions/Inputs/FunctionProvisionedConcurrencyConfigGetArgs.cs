// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Functions.Inputs
{

    public sealed class FunctionProvisionedConcurrencyConfigGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable)
        /// </summary>
        [Input("count")]
        public Input<int>? Count { get; set; }

        /// <summary>
        /// (Updatable) The strategy for provisioned concurrency to be used.
        /// </summary>
        [Input("strategy", required: true)]
        public Input<string> Strategy { get; set; } = null!;

        public FunctionProvisionedConcurrencyConfigGetArgs()
        {
        }
        public static new FunctionProvisionedConcurrencyConfigGetArgs Empty => new FunctionProvisionedConcurrencyConfigGetArgs();
    }
}