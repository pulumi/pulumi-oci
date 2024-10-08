// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagement.Inputs
{

    public sealed class ManagedInstanceManagedInstanceGroupArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// User friendly name
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// software source identifier
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        public ManagedInstanceManagedInstanceGroupArgs()
        {
        }
        public static new ManagedInstanceManagedInstanceGroupArgs Empty => new ManagedInstanceManagedInstanceGroupArgs();
    }
}
