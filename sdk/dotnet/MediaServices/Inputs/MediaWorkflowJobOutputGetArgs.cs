// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.MediaServices.Inputs
{

    public sealed class MediaWorkflowJobOutputGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Type of job output.
        /// </summary>
        [Input("assetType")]
        public Input<string>? AssetType { get; set; }

        /// <summary>
        /// The bucket name of the job output.
        /// </summary>
        [Input("bucket")]
        public Input<string>? Bucket { get; set; }

        /// <summary>
        /// The ID associated with the job output.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// The namespace name of the job output.
        /// </summary>
        [Input("namespace")]
        public Input<string>? Namespace { get; set; }

        /// <summary>
        /// The object name of the job output.
        /// </summary>
        [Input("object")]
        public Input<string>? Object { get; set; }

        public MediaWorkflowJobOutputGetArgs()
        {
        }
        public static new MediaWorkflowJobOutputGetArgs Empty => new MediaWorkflowJobOutputGetArgs();
    }
}