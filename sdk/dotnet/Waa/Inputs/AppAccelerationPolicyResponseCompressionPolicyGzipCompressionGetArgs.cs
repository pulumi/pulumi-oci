// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waa.Inputs
{

    public sealed class AppAccelerationPolicyResponseCompressionPolicyGzipCompressionGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) When true, support for gzip compression is enabled. HTTP responses will be compressed with gzip only if the client indicates support for gzip via the "Accept-Encoding: gzip" request header.
        /// </summary>
        [Input("isEnabled")]
        public Input<bool>? IsEnabled { get; set; }

        public AppAccelerationPolicyResponseCompressionPolicyGzipCompressionGetArgs()
        {
        }
        public static new AppAccelerationPolicyResponseCompressionPolicyGzipCompressionGetArgs Empty => new AppAccelerationPolicyResponseCompressionPolicyGzipCompressionGetArgs();
    }
}