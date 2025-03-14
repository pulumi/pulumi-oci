// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagement.Inputs
{

    public sealed class ManagedInstanceGroupManagedInstanceArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Managed Instance Group identifier
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// unique identifier that is immutable on creation
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        public ManagedInstanceGroupManagedInstanceArgs()
        {
        }
        public static new ManagedInstanceGroupManagedInstanceArgs Empty => new ManagedInstanceGroupManagedInstanceArgs();
    }
}
