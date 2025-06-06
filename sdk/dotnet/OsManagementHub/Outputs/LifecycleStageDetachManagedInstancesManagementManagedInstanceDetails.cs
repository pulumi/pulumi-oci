// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub.Outputs
{

    [OutputType]
    public sealed class LifecycleStageDetachManagedInstancesManagementManagedInstanceDetails
    {
        /// <summary>
        /// The list of managed instance OCIDs to be attached/detached.
        /// </summary>
        public readonly ImmutableArray<string> ManagedInstances;
        /// <summary>
        /// Provides the name and description of the job.
        /// </summary>
        public readonly Outputs.LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsWorkRequestDetails? WorkRequestDetails;

        [OutputConstructor]
        private LifecycleStageDetachManagedInstancesManagementManagedInstanceDetails(
            ImmutableArray<string> managedInstances,

            Outputs.LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsWorkRequestDetails? workRequestDetails)
        {
            ManagedInstances = managedInstances;
            WorkRequestDetails = workRequestDetails;
        }
    }
}
