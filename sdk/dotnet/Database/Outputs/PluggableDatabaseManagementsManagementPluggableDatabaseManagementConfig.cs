// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfig
    {
        /// <summary>
        /// (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public readonly bool EnablePluggabledatabasemanagement;
        /// <summary>
        /// The status of the Pluggable Database Management service.
        /// </summary>
        public readonly string? ManagementStatus;

        [OutputConstructor]
        private PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfig(
            bool enablePluggabledatabasemanagement,

            string? managementStatus)
        {
            EnablePluggabledatabasemanagement = enablePluggabledatabasemanagement;
            ManagementStatus = managementStatus;
        }
    }
}
