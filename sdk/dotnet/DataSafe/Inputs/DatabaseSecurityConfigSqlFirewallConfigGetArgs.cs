// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Inputs
{

    public sealed class DatabaseSecurityConfigSqlFirewallConfigGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Specifies whether the firewall should include or exclude the database internal job activities.
        /// </summary>
        [Input("excludeJob")]
        public Input<string>? ExcludeJob { get; set; }

        /// <summary>
        /// (Updatable) Specifies whether the firewall is enabled or disabled on the target database.
        /// </summary>
        [Input("status")]
        public Input<string>? Status { get; set; }

        /// <summary>
        /// The most recent time when the firewall status is updated, in the format defined by RFC3339.
        /// </summary>
        [Input("timeStatusUpdated")]
        public Input<string>? TimeStatusUpdated { get; set; }

        /// <summary>
        /// (Updatable) Specifies whether Data Safe should automatically purge the violation logs  from the database after collecting the violation logs and persisting on Data Safe.
        /// </summary>
        [Input("violationLogAutoPurge")]
        public Input<string>? ViolationLogAutoPurge { get; set; }

        public DatabaseSecurityConfigSqlFirewallConfigGetArgs()
        {
        }
        public static new DatabaseSecurityConfigSqlFirewallConfigGetArgs Empty => new DatabaseSecurityConfigSqlFirewallConfigGetArgs();
    }
}