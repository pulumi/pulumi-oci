// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Inputs
{

    public sealed class ClusterMetadataGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The user who created the cluster.
        /// </summary>
        [Input("createdByUserId")]
        public Input<string>? CreatedByUserId { get; set; }

        /// <summary>
        /// The OCID of the work request which created the cluster.
        /// </summary>
        [Input("createdByWorkRequestId")]
        public Input<string>? CreatedByWorkRequestId { get; set; }

        /// <summary>
        /// The user who deleted the cluster.
        /// </summary>
        [Input("deletedByUserId")]
        public Input<string>? DeletedByUserId { get; set; }

        /// <summary>
        /// The OCID of the work request which deleted the cluster.
        /// </summary>
        [Input("deletedByWorkRequestId")]
        public Input<string>? DeletedByWorkRequestId { get; set; }

        /// <summary>
        /// The time the cluster was created.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time the cluster was deleted.
        /// </summary>
        [Input("timeDeleted")]
        public Input<string>? TimeDeleted { get; set; }

        /// <summary>
        /// The time the cluster was updated.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        /// <summary>
        /// The user who updated the cluster.
        /// </summary>
        [Input("updatedByUserId")]
        public Input<string>? UpdatedByUserId { get; set; }

        /// <summary>
        /// The OCID of the work request which updated the cluster.
        /// </summary>
        [Input("updatedByWorkRequestId")]
        public Input<string>? UpdatedByWorkRequestId { get; set; }

        public ClusterMetadataGetArgs()
        {
        }
        public static new ClusterMetadataGetArgs Empty => new ClusterMetadataGetArgs();
    }
}