// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiAnomalyDetection.Outputs
{

    [OutputType]
    public sealed class GetDetectAnomalyJobInputDetailObjectLocationResult
    {
        /// <summary>
        /// Object Storage bucket name.
        /// </summary>
        public readonly string Bucket;
        /// <summary>
        /// Object Storage namespace.
        /// </summary>
        public readonly string Namespace;
        /// <summary>
        /// Object Storage object name.
        /// </summary>
        public readonly string Object;

        [OutputConstructor]
        private GetDetectAnomalyJobInputDetailObjectLocationResult(
            string bucket,

            string @namespace,

            string @object)
        {
            Bucket = bucket;
            Namespace = @namespace;
            Object = @object;
        }
    }
}