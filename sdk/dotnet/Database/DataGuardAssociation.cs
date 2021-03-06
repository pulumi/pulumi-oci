// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    /// <summary>
    /// This resource provides the Data Guard Association resource in Oracle Cloud Infrastructure Database service.
    /// 
    /// Creates a new Data Guard association.  A Data Guard association represents the replication relationship between the
    /// specified database and a peer database. For more information, see [Using Oracle Data Guard](https://docs.cloud.oracle.com/iaas/Content/Database/Tasks/usingdataguard.htm).
    /// 
    /// All Oracle Cloud Infrastructure resources, including Data Guard associations, get an Oracle-assigned, unique ID
    /// called an Oracle Cloud Identifier (OCID). When you create a resource, you can find its OCID in the response.
    /// You can also retrieve a resource's OCID by using a List API operation on that resource type, or by viewing the
    /// resource in the Console. For more information, see
    /// [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// class MyStack : Stack
    /// {
    ///     public MyStack()
    ///     {
    ///         var testDataGuardAssociation = new Oci.Database.DataGuardAssociation("testDataGuardAssociation", new Oci.Database.DataGuardAssociationArgs
    ///         {
    ///             CreationType = @var.Data_guard_association_creation_type,
    ///             DatabaseAdminPassword = @var.Data_guard_association_database_admin_password,
    ///             DatabaseId = oci_database_database.Test_database.Id,
    ///             DeleteStandbyDbHomeOnDelete = @var.Data_guard_association_delete_standby_db_home_on_delete,
    ///             ProtectionMode = @var.Data_guard_association_protection_mode,
    ///             TransportType = @var.Data_guard_association_transport_type,
    ///             AvailabilityDomain = @var.Data_guard_association_availability_domain,
    ///             BackupNetworkNsgIds = @var.Data_guard_association_backup_network_nsg_ids,
    ///             DatabaseSoftwareImageId = oci_database_database_software_image.Test_database_software_image.Id,
    ///             DisplayName = @var.Data_guard_association_display_name,
    ///             Hostname = @var.Data_guard_association_hostname,
    ///             IsActiveDataGuardEnabled = @var.Data_guard_association_is_active_data_guard_enabled,
    ///             NsgIds = @var.Data_guard_association_nsg_ids,
    ///             PeerDbHomeId = oci_database_db_home.Test_db_home.Id,
    ///             PeerDbSystemId = oci_database_db_system.Test_db_system.Id,
    ///             PeerDbUniqueName = @var.Data_guard_association_peer_db_unique_name,
    ///             PeerSidPrefix = @var.Data_guard_association_peer_sid_prefix,
    ///             PeerVmClusterId = oci_database_vm_cluster.Test_vm_cluster.Id,
    ///             Shape = @var.Data_guard_association_shape,
    ///             SubnetId = oci_core_subnet.Test_subnet.Id,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// Import is not supported for this resource.
    /// </summary>
    [OciResourceType("oci:Database/dataGuardAssociation:DataGuardAssociation")]
    public partial class DataGuardAssociation : Pulumi.CustomResource
    {
        /// <summary>
        /// The lag time between updates to the primary database and application of the redo data on the standby database, as computed by the reporting database.  Example: `9 seconds`
        /// </summary>
        [Output("applyLag")]
        public Output<string> ApplyLag { get; private set; } = null!;

        /// <summary>
        /// The rate at which redo logs are synced between the associated databases.  Example: `180 Mb per second`
        /// </summary>
        [Output("applyRate")]
        public Output<string> ApplyRate { get; private set; } = null!;

        /// <summary>
        /// The name of the availability domain that the standby database DB system will be located in. For example- "Uocm:PHX-AD-1".
        /// </summary>
        [Output("availabilityDomain")]
        public Output<string> AvailabilityDomain { get; private set; } = null!;

        /// <summary>
        /// A list of the [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups (NSGs) that the backup network of this DB system belongs to. Setting this to an empty array after the list is created removes the resource from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). Applicable only to Exadata systems.
        /// </summary>
        [Output("backupNetworkNsgIds")]
        public Output<ImmutableArray<string>> BackupNetworkNsgIds { get; private set; } = null!;

        [Output("createAsync")]
        public Output<bool?> CreateAsync { get; private set; } = null!;

        /// <summary>
        /// Specifies whether to create the peer database in an existing DB system or in a new DB system.
        /// </summary>
        [Output("creationType")]
        public Output<string> CreationType { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A strong password for the `SYS`, `SYSTEM`, and `PDB Admin` users to apply during standby creation.
        /// </summary>
        [Output("databaseAdminPassword")]
        public Output<string> DatabaseAdminPassword { get; private set; } = null!;

        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Output("databaseId")]
        public Output<string> DatabaseId { get; private set; } = null!;

        /// <summary>
        /// The database software image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Applicable only when creationType=`ExistingDbSystem` and when the existing database has Exadata shape.
        /// </summary>
        [Output("databaseSoftwareImageId")]
        public Output<string?> DatabaseSoftwareImageId { get; private set; } = null!;

        [Output("deleteStandbyDbHomeOnDelete")]
        public Output<string> DeleteStandbyDbHomeOnDelete { get; private set; } = null!;

        /// <summary>
        /// The user-friendly name of the DB system that will contain the the standby database. The display name does not have to be unique.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// The hostname for the DB node.
        /// </summary>
        [Output("hostname")]
        public Output<string> Hostname { get; private set; } = null!;

        /// <summary>
        /// (Updatable) True if active Data Guard is enabled.
        /// </summary>
        [Output("isActiveDataGuardEnabled")]
        public Output<bool> IsActiveDataGuardEnabled { get; private set; } = null!;

        /// <summary>
        /// Additional information about the current lifecycleState, if available.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// A list of the [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups (NSGs) that this resource belongs to. Setting this to an empty array after the list is created removes the resource from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). **NsgIds restrictions:**
        /// * Autonomous Databases with private access require at least 1 Network Security Group (NSG). The nsgIds array cannot be empty.
        /// </summary>
        [Output("nsgIds")]
        public Output<ImmutableArray<string>> NsgIds { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer database's Data Guard association.
        /// </summary>
        [Output("peerDataGuardAssociationId")]
        public Output<string> PeerDataGuardAssociationId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated peer database.
        /// </summary>
        [Output("peerDatabaseId")]
        public Output<string> PeerDatabaseId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB home in which to create the standby database. You must supply this value to create standby database with an existing DB home
        /// </summary>
        [Output("peerDbHomeId")]
        public Output<string> PeerDbHomeId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system in which to create the standby database. You must supply this value if creationType is `ExistingDbSystem`.
        /// </summary>
        [Output("peerDbSystemId")]
        public Output<string> PeerDbSystemId { get; private set; } = null!;

        /// <summary>
        /// Specifies the `DB_UNIQUE_NAME` of the peer database to be created.
        /// </summary>
        [Output("peerDbUniqueName")]
        public Output<string?> PeerDbUniqueName { get; private set; } = null!;

        /// <summary>
        /// The role of the peer database in this Data Guard association.
        /// </summary>
        [Output("peerRole")]
        public Output<string> PeerRole { get; private set; } = null!;

        /// <summary>
        /// Specifies a prefix for the `Oracle SID` of the database to be created.
        /// </summary>
        [Output("peerSidPrefix")]
        public Output<string?> PeerSidPrefix { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM Cluster in which to create the standby database. You must supply this value if creationType is `ExistingVmCluster`.
        /// </summary>
        [Output("peerVmClusterId")]
        public Output<string> PeerVmClusterId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The protection mode to set up between the primary and standby databases. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
        /// </summary>
        [Output("protectionMode")]
        public Output<string> ProtectionMode { get; private set; } = null!;

        /// <summary>
        /// The role of the reporting database in this Data Guard association.
        /// </summary>
        [Output("role")]
        public Output<string> Role { get; private set; } = null!;

        /// <summary>
        /// The virtual machine DB system shape to launch for the standby database in the Data Guard association. The shape determines the number of CPU cores and the amount of memory available for the DB system. Only virtual machine shapes are valid options. If you do not supply this parameter, the default shape is the shape of the primary DB system.
        /// </summary>
        [Output("shape")]
        public Output<string> Shape { get; private set; } = null!;

        /// <summary>
        /// The current state of the Data Guard association.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The OCID of the subnet the DB system is associated with. **Subnet Restrictions:**
        /// * For 1- and 2-node RAC DB systems, do not use a subnet that overlaps with 192.168.16.16/28
        /// </summary>
        [Output("subnetId")]
        public Output<string> SubnetId { get; private set; } = null!;

        /// <summary>
        /// The date and time the Data Guard association was created.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The redo transport type to use for this Data Guard association.  Valid values depend on the specified `protectionMode`:
        /// * MAXIMUM_AVAILABILITY - SYNC or FASTSYNC
        /// * MAXIMUM_PERFORMANCE - ASYNC
        /// * MAXIMUM_PROTECTION - SYNC
        /// </summary>
        [Output("transportType")]
        public Output<string> TransportType { get; private set; } = null!;


        /// <summary>
        /// Create a DataGuardAssociation resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public DataGuardAssociation(string name, DataGuardAssociationArgs args, CustomResourceOptions? options = null)
            : base("oci:Database/dataGuardAssociation:DataGuardAssociation", name, args ?? new DataGuardAssociationArgs(), MakeResourceOptions(options, ""))
        {
        }

        private DataGuardAssociation(string name, Input<string> id, DataGuardAssociationState? state = null, CustomResourceOptions? options = null)
            : base("oci:Database/dataGuardAssociation:DataGuardAssociation", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing DataGuardAssociation resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static DataGuardAssociation Get(string name, Input<string> id, DataGuardAssociationState? state = null, CustomResourceOptions? options = null)
        {
            return new DataGuardAssociation(name, id, state, options);
        }
    }

    public sealed class DataGuardAssociationArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The name of the availability domain that the standby database DB system will be located in. For example- "Uocm:PHX-AD-1".
        /// </summary>
        [Input("availabilityDomain")]
        public Input<string>? AvailabilityDomain { get; set; }

        [Input("backupNetworkNsgIds")]
        private InputList<string>? _backupNetworkNsgIds;

        /// <summary>
        /// A list of the [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups (NSGs) that the backup network of this DB system belongs to. Setting this to an empty array after the list is created removes the resource from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). Applicable only to Exadata systems.
        /// </summary>
        public InputList<string> BackupNetworkNsgIds
        {
            get => _backupNetworkNsgIds ?? (_backupNetworkNsgIds = new InputList<string>());
            set => _backupNetworkNsgIds = value;
        }

        [Input("createAsync")]
        public Input<bool>? CreateAsync { get; set; }

        /// <summary>
        /// Specifies whether to create the peer database in an existing DB system or in a new DB system.
        /// </summary>
        [Input("creationType", required: true)]
        public Input<string> CreationType { get; set; } = null!;

        /// <summary>
        /// (Updatable) A strong password for the `SYS`, `SYSTEM`, and `PDB Admin` users to apply during standby creation.
        /// </summary>
        [Input("databaseAdminPassword", required: true)]
        public Input<string> DatabaseAdminPassword { get; set; } = null!;

        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("databaseId", required: true)]
        public Input<string> DatabaseId { get; set; } = null!;

        /// <summary>
        /// The database software image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Applicable only when creationType=`ExistingDbSystem` and when the existing database has Exadata shape.
        /// </summary>
        [Input("databaseSoftwareImageId")]
        public Input<string>? DatabaseSoftwareImageId { get; set; }

        [Input("deleteStandbyDbHomeOnDelete", required: true)]
        public Input<string> DeleteStandbyDbHomeOnDelete { get; set; } = null!;

        /// <summary>
        /// The user-friendly name of the DB system that will contain the the standby database. The display name does not have to be unique.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The hostname for the DB node.
        /// </summary>
        [Input("hostname")]
        public Input<string>? Hostname { get; set; }

        /// <summary>
        /// (Updatable) True if active Data Guard is enabled.
        /// </summary>
        [Input("isActiveDataGuardEnabled")]
        public Input<bool>? IsActiveDataGuardEnabled { get; set; }

        [Input("nsgIds")]
        private InputList<string>? _nsgIds;

        /// <summary>
        /// A list of the [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups (NSGs) that this resource belongs to. Setting this to an empty array after the list is created removes the resource from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). **NsgIds restrictions:**
        /// * Autonomous Databases with private access require at least 1 Network Security Group (NSG). The nsgIds array cannot be empty.
        /// </summary>
        public InputList<string> NsgIds
        {
            get => _nsgIds ?? (_nsgIds = new InputList<string>());
            set => _nsgIds = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB home in which to create the standby database. You must supply this value to create standby database with an existing DB home
        /// </summary>
        [Input("peerDbHomeId")]
        public Input<string>? PeerDbHomeId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system in which to create the standby database. You must supply this value if creationType is `ExistingDbSystem`.
        /// </summary>
        [Input("peerDbSystemId")]
        public Input<string>? PeerDbSystemId { get; set; }

        /// <summary>
        /// Specifies the `DB_UNIQUE_NAME` of the peer database to be created.
        /// </summary>
        [Input("peerDbUniqueName")]
        public Input<string>? PeerDbUniqueName { get; set; }

        /// <summary>
        /// Specifies a prefix for the `Oracle SID` of the database to be created.
        /// </summary>
        [Input("peerSidPrefix")]
        public Input<string>? PeerSidPrefix { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM Cluster in which to create the standby database. You must supply this value if creationType is `ExistingVmCluster`.
        /// </summary>
        [Input("peerVmClusterId")]
        public Input<string>? PeerVmClusterId { get; set; }

        /// <summary>
        /// (Updatable) The protection mode to set up between the primary and standby databases. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
        /// </summary>
        [Input("protectionMode", required: true)]
        public Input<string> ProtectionMode { get; set; } = null!;

        /// <summary>
        /// The virtual machine DB system shape to launch for the standby database in the Data Guard association. The shape determines the number of CPU cores and the amount of memory available for the DB system. Only virtual machine shapes are valid options. If you do not supply this parameter, the default shape is the shape of the primary DB system.
        /// </summary>
        [Input("shape")]
        public Input<string>? Shape { get; set; }

        /// <summary>
        /// The OCID of the subnet the DB system is associated with. **Subnet Restrictions:**
        /// * For 1- and 2-node RAC DB systems, do not use a subnet that overlaps with 192.168.16.16/28
        /// </summary>
        [Input("subnetId")]
        public Input<string>? SubnetId { get; set; }

        /// <summary>
        /// (Updatable) The redo transport type to use for this Data Guard association.  Valid values depend on the specified `protectionMode`:
        /// * MAXIMUM_AVAILABILITY - SYNC or FASTSYNC
        /// * MAXIMUM_PERFORMANCE - ASYNC
        /// * MAXIMUM_PROTECTION - SYNC
        /// </summary>
        [Input("transportType", required: true)]
        public Input<string> TransportType { get; set; } = null!;

        public DataGuardAssociationArgs()
        {
        }
    }

    public sealed class DataGuardAssociationState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The lag time between updates to the primary database and application of the redo data on the standby database, as computed by the reporting database.  Example: `9 seconds`
        /// </summary>
        [Input("applyLag")]
        public Input<string>? ApplyLag { get; set; }

        /// <summary>
        /// The rate at which redo logs are synced between the associated databases.  Example: `180 Mb per second`
        /// </summary>
        [Input("applyRate")]
        public Input<string>? ApplyRate { get; set; }

        /// <summary>
        /// The name of the availability domain that the standby database DB system will be located in. For example- "Uocm:PHX-AD-1".
        /// </summary>
        [Input("availabilityDomain")]
        public Input<string>? AvailabilityDomain { get; set; }

        [Input("backupNetworkNsgIds")]
        private InputList<string>? _backupNetworkNsgIds;

        /// <summary>
        /// A list of the [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups (NSGs) that the backup network of this DB system belongs to. Setting this to an empty array after the list is created removes the resource from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). Applicable only to Exadata systems.
        /// </summary>
        public InputList<string> BackupNetworkNsgIds
        {
            get => _backupNetworkNsgIds ?? (_backupNetworkNsgIds = new InputList<string>());
            set => _backupNetworkNsgIds = value;
        }

        [Input("createAsync")]
        public Input<bool>? CreateAsync { get; set; }

        /// <summary>
        /// Specifies whether to create the peer database in an existing DB system or in a new DB system.
        /// </summary>
        [Input("creationType")]
        public Input<string>? CreationType { get; set; }

        /// <summary>
        /// (Updatable) A strong password for the `SYS`, `SYSTEM`, and `PDB Admin` users to apply during standby creation.
        /// </summary>
        [Input("databaseAdminPassword")]
        public Input<string>? DatabaseAdminPassword { get; set; }

        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("databaseId")]
        public Input<string>? DatabaseId { get; set; }

        /// <summary>
        /// The database software image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Applicable only when creationType=`ExistingDbSystem` and when the existing database has Exadata shape.
        /// </summary>
        [Input("databaseSoftwareImageId")]
        public Input<string>? DatabaseSoftwareImageId { get; set; }

        [Input("deleteStandbyDbHomeOnDelete")]
        public Input<string>? DeleteStandbyDbHomeOnDelete { get; set; }

        /// <summary>
        /// The user-friendly name of the DB system that will contain the the standby database. The display name does not have to be unique.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The hostname for the DB node.
        /// </summary>
        [Input("hostname")]
        public Input<string>? Hostname { get; set; }

        /// <summary>
        /// (Updatable) True if active Data Guard is enabled.
        /// </summary>
        [Input("isActiveDataGuardEnabled")]
        public Input<bool>? IsActiveDataGuardEnabled { get; set; }

        /// <summary>
        /// Additional information about the current lifecycleState, if available.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        [Input("nsgIds")]
        private InputList<string>? _nsgIds;

        /// <summary>
        /// A list of the [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups (NSGs) that this resource belongs to. Setting this to an empty array after the list is created removes the resource from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). **NsgIds restrictions:**
        /// * Autonomous Databases with private access require at least 1 Network Security Group (NSG). The nsgIds array cannot be empty.
        /// </summary>
        public InputList<string> NsgIds
        {
            get => _nsgIds ?? (_nsgIds = new InputList<string>());
            set => _nsgIds = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer database's Data Guard association.
        /// </summary>
        [Input("peerDataGuardAssociationId")]
        public Input<string>? PeerDataGuardAssociationId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated peer database.
        /// </summary>
        [Input("peerDatabaseId")]
        public Input<string>? PeerDatabaseId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB home in which to create the standby database. You must supply this value to create standby database with an existing DB home
        /// </summary>
        [Input("peerDbHomeId")]
        public Input<string>? PeerDbHomeId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system in which to create the standby database. You must supply this value if creationType is `ExistingDbSystem`.
        /// </summary>
        [Input("peerDbSystemId")]
        public Input<string>? PeerDbSystemId { get; set; }

        /// <summary>
        /// Specifies the `DB_UNIQUE_NAME` of the peer database to be created.
        /// </summary>
        [Input("peerDbUniqueName")]
        public Input<string>? PeerDbUniqueName { get; set; }

        /// <summary>
        /// The role of the peer database in this Data Guard association.
        /// </summary>
        [Input("peerRole")]
        public Input<string>? PeerRole { get; set; }

        /// <summary>
        /// Specifies a prefix for the `Oracle SID` of the database to be created.
        /// </summary>
        [Input("peerSidPrefix")]
        public Input<string>? PeerSidPrefix { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM Cluster in which to create the standby database. You must supply this value if creationType is `ExistingVmCluster`.
        /// </summary>
        [Input("peerVmClusterId")]
        public Input<string>? PeerVmClusterId { get; set; }

        /// <summary>
        /// (Updatable) The protection mode to set up between the primary and standby databases. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
        /// </summary>
        [Input("protectionMode")]
        public Input<string>? ProtectionMode { get; set; }

        /// <summary>
        /// The role of the reporting database in this Data Guard association.
        /// </summary>
        [Input("role")]
        public Input<string>? Role { get; set; }

        /// <summary>
        /// The virtual machine DB system shape to launch for the standby database in the Data Guard association. The shape determines the number of CPU cores and the amount of memory available for the DB system. Only virtual machine shapes are valid options. If you do not supply this parameter, the default shape is the shape of the primary DB system.
        /// </summary>
        [Input("shape")]
        public Input<string>? Shape { get; set; }

        /// <summary>
        /// The current state of the Data Guard association.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The OCID of the subnet the DB system is associated with. **Subnet Restrictions:**
        /// * For 1- and 2-node RAC DB systems, do not use a subnet that overlaps with 192.168.16.16/28
        /// </summary>
        [Input("subnetId")]
        public Input<string>? SubnetId { get; set; }

        /// <summary>
        /// The date and time the Data Guard association was created.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// (Updatable) The redo transport type to use for this Data Guard association.  Valid values depend on the specified `protectionMode`:
        /// * MAXIMUM_AVAILABILITY - SYNC or FASTSYNC
        /// * MAXIMUM_PERFORMANCE - ASYNC
        /// * MAXIMUM_PROTECTION - SYNC
        /// </summary>
        [Input("transportType")]
        public Input<string>? TransportType { get; set; }

        public DataGuardAssociationState()
        {
        }
    }
}
