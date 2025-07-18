// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Mysql.Inputs
{

    public sealed class MysqlBackupDbSystemSnapshotArgs : global::Pulumi.ResourceArgs
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
        private InputList<Inputs.MysqlBackupDbSystemSnapshotBackupPolicyArgs>? _backupPolicies;

        /// <summary>
        /// The Backup policy for the DB System.
        /// </summary>
        public InputList<Inputs.MysqlBackupDbSystemSnapshotBackupPolicyArgs> BackupPolicies
        {
            get => _backupPolicies ?? (_backupPolicies = new InputList<Inputs.MysqlBackupDbSystemSnapshotBackupPolicyArgs>());
            set => _backupPolicies = value;
        }

        /// <summary>
        /// (Updatable) The OCID of the compartment the backup exists in.
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
        /// DEPRECATED: User specified size of the data volume. May be less than current allocatedStorageSizeInGBs. Replaced by dataStorage.dataStorageSizeInGBs.
        /// </summary>
        [Input("dataStorageSizeInGb")]
        public Input<int>? DataStorageSizeInGb { get; set; }

        [Input("dataStorages")]
        private InputList<Inputs.MysqlBackupDbSystemSnapshotDataStorageArgs>? _dataStorages;

        /// <summary>
        /// Data Storage information.
        /// </summary>
        public InputList<Inputs.MysqlBackupDbSystemSnapshotDataStorageArgs> DataStorages
        {
            get => _dataStorages ?? (_dataStorages = new InputList<Inputs.MysqlBackupDbSystemSnapshotDataStorageArgs>());
            set => _dataStorages = value;
        }

        /// <summary>
        /// Whether to enable monitoring via the Database Management service.
        /// </summary>
        [Input("databaseManagement")]
        public Input<string>? DatabaseManagement { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        [Input("deletionPolicies")]
        private InputList<Inputs.MysqlBackupDbSystemSnapshotDeletionPolicyArgs>? _deletionPolicies;

        /// <summary>
        /// The Deletion policy for the DB System.
        /// </summary>
        public InputList<Inputs.MysqlBackupDbSystemSnapshotDeletionPolicyArgs> DeletionPolicies
        {
            get => _deletionPolicies ?? (_deletionPolicies = new InputList<Inputs.MysqlBackupDbSystemSnapshotDeletionPolicyArgs>());
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

        [Input("encryptDatas")]
        private InputList<Inputs.MysqlBackupDbSystemSnapshotEncryptDataArgs>? _encryptDatas;

        /// <summary>
        /// Encrypt data details.
        /// </summary>
        public InputList<Inputs.MysqlBackupDbSystemSnapshotEncryptDataArgs> EncryptDatas
        {
            get => _encryptDatas ?? (_encryptDatas = new InputList<Inputs.MysqlBackupDbSystemSnapshotEncryptDataArgs>());
            set => _encryptDatas = value;
        }

        [Input("endpoints")]
        private InputList<Inputs.MysqlBackupDbSystemSnapshotEndpointArgs>? _endpoints;

        /// <summary>
        /// The network endpoints available for this DB System.
        /// </summary>
        public InputList<Inputs.MysqlBackupDbSystemSnapshotEndpointArgs> Endpoints
        {
            get => _endpoints ?? (_endpoints = new InputList<Inputs.MysqlBackupDbSystemSnapshotEndpointArgs>());
            set => _endpoints = value;
        }

        /// <summary>
        /// The name of the Fault Domain the DB System is located in.
        /// </summary>
        [Input("faultDomain")]
        public Input<string>? FaultDomain { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
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
        private InputList<Inputs.MysqlBackupDbSystemSnapshotMaintenanceArgs>? _maintenances;

        /// <summary>
        /// The Maintenance Policy for the DB System or Read Replica that this model is included in.
        /// </summary>
        public InputList<Inputs.MysqlBackupDbSystemSnapshotMaintenanceArgs> Maintenances
        {
            get => _maintenances ?? (_maintenances = new InputList<Inputs.MysqlBackupDbSystemSnapshotMaintenanceArgs>());
            set => _maintenances = value;
        }

        /// <summary>
        /// The MySQL server version of the DB System used for backup.
        /// </summary>
        [Input("mysqlVersion")]
        public Input<string>? MysqlVersion { get; set; }

        [Input("nsgIds")]
        private InputList<string>? _nsgIds;

        /// <summary>
        /// Network Security Group OCIDs used for the VNIC attachment.
        /// </summary>
        public InputList<string> NsgIds
        {
            get => _nsgIds ?? (_nsgIds = new InputList<string>());
            set => _nsgIds = value;
        }

        /// <summary>
        /// The port for REST to listen on. Supported port numbers are 443 and from 1024 to 65535.
        /// </summary>
        [Input("port")]
        public Input<int>? Port { get; set; }

        /// <summary>
        /// The network port on which X Plugin listens for TCP/IP connections. This is the X Plugin equivalent of port.
        /// </summary>
        [Input("portX")]
        public Input<int>? PortX { get; set; }

        [Input("readEndpoints")]
        private InputList<Inputs.MysqlBackupDbSystemSnapshotReadEndpointArgs>? _readEndpoints;

        /// <summary>
        /// The read endpoint of a DB System.
        /// </summary>
        public InputList<Inputs.MysqlBackupDbSystemSnapshotReadEndpointArgs> ReadEndpoints
        {
            get => _readEndpoints ?? (_readEndpoints = new InputList<Inputs.MysqlBackupDbSystemSnapshotReadEndpointArgs>());
            set => _readEndpoints = value;
        }

        /// <summary>
        /// The region identifier of the region where the DB system exists. For more information, please see [Regions and Availability Domains](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm).
        /// </summary>
        [Input("region")]
        public Input<string>? Region { get; set; }

        [Input("rests")]
        private InputList<Inputs.MysqlBackupDbSystemSnapshotRestArgs>? _rests;

        /// <summary>
        /// REST configuration details.
        /// </summary>
        public InputList<Inputs.MysqlBackupDbSystemSnapshotRestArgs> Rests
        {
            get => _rests ?? (_rests = new InputList<Inputs.MysqlBackupDbSystemSnapshotRestArgs>());
            set => _rests = value;
        }

        [Input("secureConnections")]
        private InputList<Inputs.MysqlBackupDbSystemSnapshotSecureConnectionArgs>? _secureConnections;

        /// <summary>
        /// Secure connection configuration details.
        /// </summary>
        public InputList<Inputs.MysqlBackupDbSystemSnapshotSecureConnectionArgs> SecureConnections
        {
            get => _secureConnections ?? (_secureConnections = new InputList<Inputs.MysqlBackupDbSystemSnapshotSecureConnectionArgs>());
            set => _secureConnections = value;
        }

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

        public MysqlBackupDbSystemSnapshotArgs()
        {
        }
        public static new MysqlBackupDbSystemSnapshotArgs Empty => new MysqlBackupDbSystemSnapshotArgs();
    }
}
