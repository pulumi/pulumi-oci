// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring.Outputs
{

    [OutputType]
    public sealed class GetConfigDynamicGroupResult
    {
        /// <summary>
        /// Identity domain name
        /// </summary>
        public readonly string Domain;
        /// <summary>
        /// Name of user Group
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Assignment of dynamic group in context of Stack Monitoring service. It describes the purpose of dynamic groups in Stack Monitoring.
        /// </summary>
        public readonly string StackMonitoringAssignment;

        [OutputConstructor]
        private GetConfigDynamicGroupResult(
            string domain,

            string name,

            string stackMonitoringAssignment)
        {
            Domain = domain;
            Name = name;
            StackMonitoringAssignment = stackMonitoringAssignment;
        }
    }
}
