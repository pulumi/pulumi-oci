// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Inputs
{

    public sealed class CloudGuardDataSourceDataSourceDetailsQueryStartTimeArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Time when the query can start, if not specified it can start immediately.
        /// </summary>
        [Input("queryStartTime")]
        public Input<string>? QueryStartTime { get; set; }

        /// <summary>
        /// (Updatable) policy used for deciding the query start time
        /// </summary>
        [Input("startPolicyType", required: true)]
        public Input<string> StartPolicyType { get; set; } = null!;

        public CloudGuardDataSourceDataSourceDetailsQueryStartTimeArgs()
        {
        }
        public static new CloudGuardDataSourceDataSourceDetailsQueryStartTimeArgs Empty => new CloudGuardDataSourceDataSourceDetailsQueryStartTimeArgs();
    }
}