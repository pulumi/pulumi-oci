// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Mysql.Inputs
{

    public sealed class MysqlBackupDbSystemSnapshotGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The username for the administrative user.
        /// </summary>
        [Input("adminUsername")]
        public Input<string>? AdminUsername { get; set; }

        /// <summary>
        /// The Availability Domain where the primary DB System should be located.
        /// </summary>
        [Input("availabilityDomain")]
        public Input<string>? AvailabilityDomain { get; set; }

        [Input("backupPolicies")]
        private InputList<Inputs.MysqlBackupDbSystemSnapshotBackupPolicyGetArgs>? _backupPolicies;

        /// <summary>
        /// The Backup policy for the DB System.
        /// </summary>
        public InputList<Inputs.MysqlBackupDbSystemSnapshotBackupPolicyGetArgs> BackupPolicies
        {
            get => _backupPolicies ?? (_backupPolicies = new InputList<Inputs.MysqlBackupDbSystemSnapshotBackupPolicyGetArgs>());
            set => _backupPolicies = value;
        }

        /// <summary>
        /// (Updatable) The OCID of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The OCID of the Configuration to be used for Instances in this DB System.
        /// </summary>
        [Input("configurationId")]
        public Input<string>? ConfigurationId { get; set; }

        /// <summary>
        /// Whether to run the DB System with InnoDB Redo Logs and the Double Write Buffer enabled or disabled, and whether to enable or disable syncing of the Binary Logs.
        /// </summary>
        [Input("crashRecovery")]
        public Input<string>? CrashRecovery { get; set; }

        /// <summary>
        /// Initial size of the data volume in GiBs that will be created and attached.
        /// </summary>
        [Input("dataStorageSizeInGb")]
        public Input<int>? DataStorageSizeInGb { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        [Input("deletionPolicies")]
        private InputList<Inputs.MysqlBackupDbSystemSnapshotDeletionPolicyGetArgs>? _deletionPolicies;

        /// <summary>
        /// The Deletion policy for the DB System.
        /// </summary>
        public InputList<Inputs.MysqlBackupDbSystemSnapshotDeletionPolicyGetArgs> DeletionPolicies
        {
            get => _deletionPolicies ?? (_deletionPolicies = new InputList<Inputs.MysqlBackupDbSystemSnapshotDeletionPolicyGetArgs>());
            set => _deletionPolicies = value;
        }

        /// <summary>
        /// (Updatable) A user-supplied description for the backup.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) A user-supplied display name for the backup.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("endpoints")]
        private InputList<Inputs.MysqlBackupDbSystemSnapshotEndpointGetArgs>? _endpoints;

        /// <summary>
        /// The network endpoints available for this DB System.
        /// </summary>
        public InputList<Inputs.MysqlBackupDbSystemSnapshotEndpointGetArgs> Endpoints
        {
            get => _endpoints ?? (_endpoints = new InputList<Inputs.MysqlBackupDbSystemSnapshotEndpointGetArgs>());
            set => _endpoints = value;
        }

        /// <summary>
        /// The name of the Fault Domain the DB System is located in.
        /// </summary>
        [Input("faultDomain")]
        public Input<string>? FaultDomain { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// The hostname for the primary endpoint of the DB System. Used for DNS. The value is the hostname portion of the primary private IP's fully qualified domain name (FQDN) (for example, "dbsystem-1" in FQDN "dbsystem-1.subnet123.vcn1.oraclevcn.com"). Must be unique across all VNICs in the subnet and comply with RFC 952 and RFC 1123.
        /// </summary>
        [Input("hostnameLabel")]
        public Input<string>? HostnameLabel { get; set; }

        /// <summary>
        /// OCID of the backup itself
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// The IP address the DB System is configured to listen on. A private IP address of the primary endpoint of the DB System. Must be an available IP address within the subnet's CIDR. This will be a "dotted-quad" style IPv4 address.
        /// </summary>
        [Input("ipAddress")]
        public Input<string>? IpAddress { get; set; }

        /// <summary>
        /// Specifies if the DB System is highly available.
        /// </summary>
        [Input("isHighlyAvailable")]
        public Input<bool>? IsHighlyAvailable { get; set; }

        [Input("maintenances")]
        private InputList<Inputs.MysqlBackupDbSystemSnapshotMaintenanceGetArgs>? _maintenances;

        /// <summary>
        /// The Maintenance Policy for the DB System.
        /// </summary>
        public InputList<Inputs.MysqlBackupDbSystemSnapshotMaintenanceGetArgs> Maintenances
        {
            get => _maintenances ?? (_maintenances = new InputList<Inputs.MysqlBackupDbSystemSnapshotMaintenanceGetArgs>());
            set => _maintenances = value;
        }

        /// <summary>
        /// The MySQL server version of the DB System used for backup.
        /// </summary>
        [Input("mysqlVersion")]
        public Input<string>? MysqlVersion { get; set; }

        /// <summary>
        /// The port for primary endpoint of the DB System to listen on.
        /// </summary>
        [Input("port")]
        public Input<int>? Port { get; set; }

        /// <summary>
        /// The network port on which X Plugin listens for TCP/IP connections. This is the X Plugin equivalent of port.
        /// </summary>
        [Input("portX")]
        public Input<int>? PortX { get; set; }

        /// <summary>
        /// The shape of the DB System instance used for backup.
        /// </summary>
        [Input("shapeName")]
        public Input<string>? ShapeName { get; set; }

        /// <summary>
        /// The OCID of the subnet the DB System is associated with.
        /// </summary>
        [Input("subnetId")]
        public Input<string>? SubnetId { get; set; }

        public MysqlBackupDbSystemSnapshotGetArgs()
        {
        }
        public static new MysqlBackupDbSystemSnapshotGetArgs Empty => new MysqlBackupDbSystemSnapshotGetArgs();
    }
}