// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.MeteringComputation.Outputs
{

    [OutputType]
    public sealed class GetScheduleResultLocationResult
    {
        /// <summary>
        /// The bucket name where usage/cost CSVs will be uploaded
        /// </summary>
        public readonly string Bucket;
        /// <summary>
        /// Defines the type of location where the usage/cost CSVs will be stored
        /// </summary>
        public readonly string LocationType;
        /// <summary>
        /// The namespace needed to determine object storage bucket.
        /// </summary>
        public readonly string Namespace;
        /// <summary>
        /// The destination Object Store Region specified by customer
        /// </summary>
        public readonly string Region;

        [OutputConstructor]
        private GetScheduleResultLocationResult(
            string bucket,

            string locationType,

            string @namespace,

            string region)
        {
            Bucket = bucket;
            LocationType = locationType;
            Namespace = @namespace;
            Region = region;
        }
    }
}