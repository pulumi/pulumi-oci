// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfigArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
        /// </summary>
        [Input("enablePluggabledatabasemanagement", required: true)]
        public Input<bool> EnablePluggabledatabasemanagement { get; set; } = null!;

        /// <summary>
        /// The status of the Pluggable Database Management service.
        /// </summary>
        [Input("managementStatus")]
        public Input<string>? ManagementStatus { get; set; }

        public PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfigArgs()
        {
        }
        public static new PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfigArgs Empty => new PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfigArgs();
    }
}