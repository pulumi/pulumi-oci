// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"fmt"

	"github.com/blang/semver"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type module struct {
	version semver.Version
}

func (m *module) Version() semver.Version {
	return m.version
}

func (m *module) Construct(ctx *pulumi.Context, name, typ, urn string) (r pulumi.Resource, err error) {
	switch typ {
	case "oci:Database/applicationVip:ApplicationVip":
		r = &ApplicationVip{}
	case "oci:Database/autonomousContainerDatabase:AutonomousContainerDatabase":
		r = &AutonomousContainerDatabase{}
	case "oci:Database/autonomousContainerDatabaseAddStandby:AutonomousContainerDatabaseAddStandby":
		r = &AutonomousContainerDatabaseAddStandby{}
	case "oci:Database/autonomousContainerDatabaseDataguardAssociation:AutonomousContainerDatabaseDataguardAssociation":
		r = &AutonomousContainerDatabaseDataguardAssociation{}
	case "oci:Database/autonomousContainerDatabaseDataguardAssociationOperation:AutonomousContainerDatabaseDataguardAssociationOperation":
		r = &AutonomousContainerDatabaseDataguardAssociationOperation{}
	case "oci:Database/autonomousContainerDatabaseDataguardRoleChange:AutonomousContainerDatabaseDataguardRoleChange":
		r = &AutonomousContainerDatabaseDataguardRoleChange{}
	case "oci:Database/autonomousContainerDatabaseSnapshotStandby:AutonomousContainerDatabaseSnapshotStandby":
		r = &AutonomousContainerDatabaseSnapshotStandby{}
	case "oci:Database/autonomousDatabase:AutonomousDatabase":
		r = &AutonomousDatabase{}
	case "oci:Database/autonomousDatabaseBackup:AutonomousDatabaseBackup":
		r = &AutonomousDatabaseBackup{}
	case "oci:Database/autonomousDatabaseInstanceWalletManagement:AutonomousDatabaseInstanceWalletManagement":
		r = &AutonomousDatabaseInstanceWalletManagement{}
	case "oci:Database/autonomousDatabaseRegionalWalletManagement:AutonomousDatabaseRegionalWalletManagement":
		r = &AutonomousDatabaseRegionalWalletManagement{}
	case "oci:Database/autonomousDatabaseSaasAdminUser:AutonomousDatabaseSaasAdminUser":
		r = &AutonomousDatabaseSaasAdminUser{}
	case "oci:Database/autonomousDatabaseSoftwareImage:AutonomousDatabaseSoftwareImage":
		r = &AutonomousDatabaseSoftwareImage{}
	case "oci:Database/autonomousDatabaseWallet:AutonomousDatabaseWallet":
		r = &AutonomousDatabaseWallet{}
	case "oci:Database/autonomousExadataInfrastructure:AutonomousExadataInfrastructure":
		r = &AutonomousExadataInfrastructure{}
	case "oci:Database/autonomousVmCluster:AutonomousVmCluster":
		r = &AutonomousVmCluster{}
	case "oci:Database/autonomousVmClusterOrdsCertificateManagement:AutonomousVmClusterOrdsCertificateManagement":
		r = &AutonomousVmClusterOrdsCertificateManagement{}
	case "oci:Database/autonomousVmClusterSslCertificateManagement:AutonomousVmClusterSslCertificateManagement":
		r = &AutonomousVmClusterSslCertificateManagement{}
	case "oci:Database/backup:Backup":
		r = &Backup{}
	case "oci:Database/backupCancelManagement:BackupCancelManagement":
		r = &BackupCancelManagement{}
	case "oci:Database/backupDestination:BackupDestination":
		r = &BackupDestination{}
	case "oci:Database/cloudAutonomousVmCluster:CloudAutonomousVmCluster":
		r = &CloudAutonomousVmCluster{}
	case "oci:Database/cloudDatabaseManagement:CloudDatabaseManagement":
		r = &CloudDatabaseManagement{}
	case "oci:Database/cloudExadataInfrastructure:CloudExadataInfrastructure":
		r = &CloudExadataInfrastructure{}
	case "oci:Database/cloudVmCluster:CloudVmCluster":
		r = &CloudVmCluster{}
	case "oci:Database/cloudVmClusterIormConfig:CloudVmClusterIormConfig":
		r = &CloudVmClusterIormConfig{}
	case "oci:Database/dataGuardAssociation:DataGuardAssociation":
		r = &DataGuardAssociation{}
	case "oci:Database/database:Database":
		r = &Database{}
	case "oci:Database/databaseSoftwareImage:DatabaseSoftwareImage":
		r = &DatabaseSoftwareImage{}
	case "oci:Database/databaseUpgrade:DatabaseUpgrade":
		r = &DatabaseUpgrade{}
	case "oci:Database/dbHome:DbHome":
		r = &DbHome{}
	case "oci:Database/dbNode:DbNode":
		r = &DbNode{}
	case "oci:Database/dbNodeConsoleConnection:DbNodeConsoleConnection":
		r = &DbNodeConsoleConnection{}
	case "oci:Database/dbNodeConsoleHistory:DbNodeConsoleHistory":
		r = &DbNodeConsoleHistory{}
	case "oci:Database/dbSystem:DbSystem":
		r = &DbSystem{}
	case "oci:Database/dbSystemsUpgrade:DbSystemsUpgrade":
		r = &DbSystemsUpgrade{}
	case "oci:Database/exadataInfrastructure:ExadataInfrastructure":
		r = &ExadataInfrastructure{}
	case "oci:Database/exadataInfrastructureCompute:ExadataInfrastructureCompute":
		r = &ExadataInfrastructureCompute{}
	case "oci:Database/exadataInfrastructureConfigureExascaleManagement:ExadataInfrastructureConfigureExascaleManagement":
		r = &ExadataInfrastructureConfigureExascaleManagement{}
	case "oci:Database/exadataInfrastructureStorage:ExadataInfrastructureStorage":
		r = &ExadataInfrastructureStorage{}
	case "oci:Database/exadataIormConfig:ExadataIormConfig":
		r = &ExadataIormConfig{}
	case "oci:Database/exadbVmCluster:ExadbVmCluster":
		r = &ExadbVmCluster{}
	case "oci:Database/exascaleDbStorageVault:ExascaleDbStorageVault":
		r = &ExascaleDbStorageVault{}
	case "oci:Database/executionAction:ExecutionAction":
		r = &ExecutionAction{}
	case "oci:Database/executionWindow:ExecutionWindow":
		r = &ExecutionWindow{}
	case "oci:Database/externalContainerDatabase:ExternalContainerDatabase":
		r = &ExternalContainerDatabase{}
	case "oci:Database/externalContainerDatabaseManagement:ExternalContainerDatabaseManagement":
		r = &ExternalContainerDatabaseManagement{}
	case "oci:Database/externalContainerDatabasesStackMonitoring:ExternalContainerDatabasesStackMonitoring":
		r = &ExternalContainerDatabasesStackMonitoring{}
	case "oci:Database/externalDatabaseConnector:ExternalDatabaseConnector":
		r = &ExternalDatabaseConnector{}
	case "oci:Database/externalNonContainerDatabase:ExternalNonContainerDatabase":
		r = &ExternalNonContainerDatabase{}
	case "oci:Database/externalNonContainerDatabaseManagement:ExternalNonContainerDatabaseManagement":
		r = &ExternalNonContainerDatabaseManagement{}
	case "oci:Database/externalNonContainerDatabaseOperationsInsightsManagement:ExternalNonContainerDatabaseOperationsInsightsManagement":
		r = &ExternalNonContainerDatabaseOperationsInsightsManagement{}
	case "oci:Database/externalNonContainerDatabasesStackMonitoring:ExternalNonContainerDatabasesStackMonitoring":
		r = &ExternalNonContainerDatabasesStackMonitoring{}
	case "oci:Database/externalPluggableDatabase:ExternalPluggableDatabase":
		r = &ExternalPluggableDatabase{}
	case "oci:Database/externalPluggableDatabaseManagement:ExternalPluggableDatabaseManagement":
		r = &ExternalPluggableDatabaseManagement{}
	case "oci:Database/externalPluggableDatabaseOperationsInsightsManagement:ExternalPluggableDatabaseOperationsInsightsManagement":
		r = &ExternalPluggableDatabaseOperationsInsightsManagement{}
	case "oci:Database/externalPluggableDatabasesStackMonitoring:ExternalPluggableDatabasesStackMonitoring":
		r = &ExternalPluggableDatabasesStackMonitoring{}
	case "oci:Database/keyStore:KeyStore":
		r = &KeyStore{}
	case "oci:Database/maintenanceRun:MaintenanceRun":
		r = &MaintenanceRun{}
	case "oci:Database/oneoffPatch:OneoffPatch":
		r = &OneoffPatch{}
	case "oci:Database/pluggableDatabase:PluggableDatabase":
		r = &PluggableDatabase{}
	case "oci:Database/pluggableDatabaseManagementsManagement:PluggableDatabaseManagementsManagement":
		r = &PluggableDatabaseManagementsManagement{}
	case "oci:Database/pluggableDatabasesLocalClone:PluggableDatabasesLocalClone":
		r = &PluggableDatabasesLocalClone{}
	case "oci:Database/pluggableDatabasesRemoteClone:PluggableDatabasesRemoteClone":
		r = &PluggableDatabasesRemoteClone{}
	case "oci:Database/scheduledAction:ScheduledAction":
		r = &ScheduledAction{}
	case "oci:Database/schedulingPlan:SchedulingPlan":
		r = &SchedulingPlan{}
	case "oci:Database/schedulingPolicy:SchedulingPolicy":
		r = &SchedulingPolicy{}
	case "oci:Database/schedulingPolicySchedulingWindow:SchedulingPolicySchedulingWindow":
		r = &SchedulingPolicySchedulingWindow{}
	case "oci:Database/vmCluster:VmCluster":
		r = &VmCluster{}
	case "oci:Database/vmClusterAddVirtualNetwork:VmClusterAddVirtualNetwork":
		r = &VmClusterAddVirtualNetwork{}
	case "oci:Database/vmClusterNetwork:VmClusterNetwork":
		r = &VmClusterNetwork{}
	case "oci:Database/vmClusterRemoveVirtualMachine:VmClusterRemoveVirtualMachine":
		r = &VmClusterRemoveVirtualMachine{}
	default:
		return nil, fmt.Errorf("unknown resource type: %s", typ)
	}

	err = ctx.RegisterResource(typ, name, nil, r, pulumi.URN_(urn))
	return
}

func init() {
	version, err := internal.PkgVersion()
	if err != nil {
		version = semver.Version{Major: 1}
	}
	pulumi.RegisterResourceModule(
		"oci",
		"Database/applicationVip",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/autonomousContainerDatabase",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/autonomousContainerDatabaseAddStandby",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/autonomousContainerDatabaseDataguardAssociation",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/autonomousContainerDatabaseDataguardAssociationOperation",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/autonomousContainerDatabaseDataguardRoleChange",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/autonomousContainerDatabaseSnapshotStandby",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/autonomousDatabase",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/autonomousDatabaseBackup",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/autonomousDatabaseInstanceWalletManagement",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/autonomousDatabaseRegionalWalletManagement",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/autonomousDatabaseSaasAdminUser",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/autonomousDatabaseSoftwareImage",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/autonomousDatabaseWallet",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/autonomousExadataInfrastructure",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/autonomousVmCluster",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/autonomousVmClusterOrdsCertificateManagement",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/autonomousVmClusterSslCertificateManagement",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/backup",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/backupCancelManagement",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/backupDestination",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/cloudAutonomousVmCluster",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/cloudDatabaseManagement",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/cloudExadataInfrastructure",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/cloudVmCluster",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/cloudVmClusterIormConfig",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/dataGuardAssociation",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/database",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/databaseSoftwareImage",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/databaseUpgrade",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/dbHome",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/dbNode",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/dbNodeConsoleConnection",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/dbNodeConsoleHistory",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/dbSystem",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/dbSystemsUpgrade",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/exadataInfrastructure",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/exadataInfrastructureCompute",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/exadataInfrastructureConfigureExascaleManagement",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/exadataInfrastructureStorage",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/exadataIormConfig",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/exadbVmCluster",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/exascaleDbStorageVault",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/executionAction",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/executionWindow",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/externalContainerDatabase",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/externalContainerDatabaseManagement",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/externalContainerDatabasesStackMonitoring",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/externalDatabaseConnector",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/externalNonContainerDatabase",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/externalNonContainerDatabaseManagement",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/externalNonContainerDatabaseOperationsInsightsManagement",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/externalNonContainerDatabasesStackMonitoring",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/externalPluggableDatabase",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/externalPluggableDatabaseManagement",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/externalPluggableDatabaseOperationsInsightsManagement",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/externalPluggableDatabasesStackMonitoring",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/keyStore",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/maintenanceRun",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/oneoffPatch",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/pluggableDatabase",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/pluggableDatabaseManagementsManagement",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/pluggableDatabasesLocalClone",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/pluggableDatabasesRemoteClone",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/scheduledAction",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/schedulingPlan",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/schedulingPolicy",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/schedulingPolicySchedulingWindow",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/vmCluster",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/vmClusterAddVirtualNetwork",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/vmClusterNetwork",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"Database/vmClusterRemoveVirtualMachine",
		&module{version},
	)
}
