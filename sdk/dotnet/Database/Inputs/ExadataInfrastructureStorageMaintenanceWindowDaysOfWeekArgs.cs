// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class ExadataInfrastructureStorageMaintenanceWindowDaysOfWeekArgs : global::Pulumi.ResourceArgs
    {
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        public ExadataInfrastructureStorageMaintenanceWindowDaysOfWeekArgs()
        {
        }
        public static new ExadataInfrastructureStorageMaintenanceWindowDaysOfWeekArgs Empty => new ExadataInfrastructureStorageMaintenanceWindowDaysOfWeekArgs();
    }
}