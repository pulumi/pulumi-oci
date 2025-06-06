// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Mysql.Inputs
{

    public sealed class ReplicaReplicaOverridesArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the Configuration to be used by the read replica.
        /// </summary>
        [Input("configurationId")]
        public Input<string>? ConfigurationId { get; set; }

        /// <summary>
        /// (Updatable) The MySQL version to be used by the read replica.
        /// </summary>
        [Input("mysqlVersion")]
        public Input<string>? MysqlVersion { get; set; }

        [Input("nsgIds")]
        private InputList<string>? _nsgIds;

        /// <summary>
        /// (Updatable) Network Security Group OCIDs used for the VNIC attachment.
        /// </summary>
        public InputList<string> NsgIds
        {
            get => _nsgIds ?? (_nsgIds = new InputList<string>());
            set => _nsgIds = value;
        }

        /// <summary>
        /// (Updatable) The shape to be used by the read replica. The shape determines the resources allocated:  CPU cores and memory for VM shapes, CPU cores, memory and storage for non-VM (bare metal) shapes.  To get a list of shapes, use the [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/mysql/20190415/ShapeSummary/ListShapes) operation. 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("shapeName")]
        public Input<string>? ShapeName { get; set; }

        public ReplicaReplicaOverridesArgs()
        {
        }
        public static new ReplicaReplicaOverridesArgs Empty => new ReplicaReplicaOverridesArgs();
    }
}
