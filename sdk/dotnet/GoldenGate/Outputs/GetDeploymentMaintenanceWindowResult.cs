// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GoldenGate.Outputs
{

    [OutputType]
    public sealed class GetDeploymentMaintenanceWindowResult
    {
        /// <summary>
        /// Days of the week.
        /// </summary>
        public readonly string Day;
        /// <summary>
        /// Start hour for maintenance period. Hour is in UTC.
        /// </summary>
        public readonly int StartHour;

        [OutputConstructor]
        private GetDeploymentMaintenanceWindowResult(
            string day,

            int startHour)
        {
            Day = day;
            StartHour = startHour;
        }
    }
}