// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class DbSystemDataCollectionOptionsGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Indicates whether diagnostic collection is enabled for the VM cluster/Cloud VM cluster/VMBM DBCS. Enabling diagnostic collection allows you to receive Events service notifications for guest VM issues. Diagnostic collection also allows Oracle to provide enhanced service and proactive support for your Exadata system. You can enable diagnostic collection during VM cluster/Cloud VM cluster provisioning. You can also disable or enable it at any time using the `UpdateVmCluster` or `updateCloudVmCluster` API.
        /// </summary>
        [Input("isDiagnosticsEventsEnabled")]
        public Input<bool>? IsDiagnosticsEventsEnabled { get; set; }

        /// <summary>
        /// (Updatable) Indicates whether health monitoring is enabled for the VM cluster / Cloud VM cluster / VMBM DBCS. Enabling health monitoring allows Oracle to collect diagnostic data and share it with its operations and support personnel. You may also receive notifications for some events. Collecting health diagnostics enables Oracle to provide proactive support and enhanced service for your system. Optionally enable health monitoring while provisioning a system. You can also disable or enable health monitoring anytime using the `UpdateVmCluster`, `UpdateCloudVmCluster` or `updateDbsystem` API.
        /// </summary>
        [Input("isHealthMonitoringEnabled")]
        public Input<bool>? IsHealthMonitoringEnabled { get; set; }

        /// <summary>
        /// (Updatable) Indicates whether incident logs and trace collection are enabled for the VM cluster / Cloud VM cluster / VMBM DBCS. Enabling incident logs collection allows Oracle to receive Events service notifications for guest VM issues, collect incident logs and traces, and use them to diagnose issues and resolve them. Optionally enable incident logs collection while provisioning a system. You can also disable or enable incident logs collection anytime using the `UpdateVmCluster`, `updateCloudVmCluster` or `updateDbsystem` API.
        /// </summary>
        [Input("isIncidentLogsEnabled")]
        public Input<bool>? IsIncidentLogsEnabled { get; set; }

        public DbSystemDataCollectionOptionsGetArgs()
        {
        }
        public static new DbSystemDataCollectionOptionsGetArgs Empty => new DbSystemDataCollectionOptionsGetArgs();
    }
}