// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Autonomous Container Database Dataguard Association resource in Oracle Cloud Infrastructure Database service.
//
// Gets an Autonomous Container Database enabled with Autonomous Data Guard associated with the specified Autonomous Container Database.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Database"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Database.GetAutonomousContainerDatabaseDataguardAssociation(ctx, &database.GetAutonomousContainerDatabaseDataguardAssociationArgs{
//				AutonomousContainerDatabaseDataguardAssociationId: oci_database_autonomous_container_database_dataguard_association.Test_autonomous_container_database_dataguard_association.Id,
//				AutonomousContainerDatabaseId:                     oci_database_autonomous_container_database.Test_autonomous_container_database.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupAutonomousContainerDatabaseDataguardAssociation(ctx *pulumi.Context, args *LookupAutonomousContainerDatabaseDataguardAssociationArgs, opts ...pulumi.InvokeOption) (*LookupAutonomousContainerDatabaseDataguardAssociationResult, error) {
	var rv LookupAutonomousContainerDatabaseDataguardAssociationResult
	err := ctx.Invoke("oci:Database/getAutonomousContainerDatabaseDataguardAssociation:getAutonomousContainerDatabaseDataguardAssociation", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAutonomousContainerDatabaseDataguardAssociation.
type LookupAutonomousContainerDatabaseDataguardAssociationArgs struct {
	// The Autonomous Container Database-Autonomous Data Guard association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousContainerDatabaseDataguardAssociationId string `pulumi:"autonomousContainerDatabaseDataguardAssociationId"`
	// The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousContainerDatabaseId string `pulumi:"autonomousContainerDatabaseId"`
}

// A collection of values returned by getAutonomousContainerDatabaseDataguardAssociation.
type LookupAutonomousContainerDatabaseDataguardAssociationResult struct {
	// The lag time between updates to the primary Autonomous Container Database and application of the redo data on the standby Autonomous Container Database, as computed by the reporting database.  Example: `9 seconds`
	ApplyLag string `pulumi:"applyLag"`
	// The rate at which redo logs are synchronized between the associated Autonomous Container Databases.  Example: `180 Mb per second`
	ApplyRate                                         string `pulumi:"applyRate"`
	AutonomousContainerDatabaseDataguardAssociationId string `pulumi:"autonomousContainerDatabaseDataguardAssociationId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Container Database that has a relationship with the peer Autonomous Container Database.
	AutonomousContainerDatabaseId string `pulumi:"autonomousContainerDatabaseId"`
	// The OCID of the Autonomous Data Guard created for a given Autonomous Container Database.
	Id string `pulumi:"id"`
	// Indicates whether Automatic Failover is enabled for Autonomous Container Database Dataguard Association
	IsAutomaticFailoverEnabled bool `pulumi:"isAutomaticFailoverEnabled"`
	// Additional information about the current lifecycleState, if available.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The OCID of the peer Autonomous Container Database-Autonomous Data Guard association.
	PeerAutonomousContainerDatabaseDataguardAssociationId string `pulumi:"peerAutonomousContainerDatabaseDataguardAssociationId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer Autonomous Container Database.
	PeerAutonomousContainerDatabaseId string `pulumi:"peerAutonomousContainerDatabaseId"`
	// The current state of Autonomous Data Guard.
	PeerLifecycleState string `pulumi:"peerLifecycleState"`
	// The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled.
	PeerRole string `pulumi:"peerRole"`
	// The protection mode of this Autonomous Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
	ProtectionMode string `pulumi:"protectionMode"`
	// The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled.
	Role string `pulumi:"role"`
	// The current state of Autonomous Data Guard.
	State string `pulumi:"state"`
	// The date and time the Autonomous DataGuard association was created.
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time when the last role change action happened.
	TimeLastRoleChanged string `pulumi:"timeLastRoleChanged"`
	// The date and time of the last update to the apply lag, apply rate, and transport lag values.
	TimeLastSynced string `pulumi:"timeLastSynced"`
	// The approximate number of seconds of redo data not yet available on the standby Autonomous Container Database, as computed by the reporting database.  Example: `7 seconds`
	TransportLag string `pulumi:"transportLag"`
}

func LookupAutonomousContainerDatabaseDataguardAssociationOutput(ctx *pulumi.Context, args LookupAutonomousContainerDatabaseDataguardAssociationOutputArgs, opts ...pulumi.InvokeOption) LookupAutonomousContainerDatabaseDataguardAssociationResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupAutonomousContainerDatabaseDataguardAssociationResult, error) {
			args := v.(LookupAutonomousContainerDatabaseDataguardAssociationArgs)
			r, err := LookupAutonomousContainerDatabaseDataguardAssociation(ctx, &args, opts...)
			var s LookupAutonomousContainerDatabaseDataguardAssociationResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupAutonomousContainerDatabaseDataguardAssociationResultOutput)
}

// A collection of arguments for invoking getAutonomousContainerDatabaseDataguardAssociation.
type LookupAutonomousContainerDatabaseDataguardAssociationOutputArgs struct {
	// The Autonomous Container Database-Autonomous Data Guard association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousContainerDatabaseDataguardAssociationId pulumi.StringInput `pulumi:"autonomousContainerDatabaseDataguardAssociationId"`
	// The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousContainerDatabaseId pulumi.StringInput `pulumi:"autonomousContainerDatabaseId"`
}

func (LookupAutonomousContainerDatabaseDataguardAssociationOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupAutonomousContainerDatabaseDataguardAssociationArgs)(nil)).Elem()
}

// A collection of values returned by getAutonomousContainerDatabaseDataguardAssociation.
type LookupAutonomousContainerDatabaseDataguardAssociationResultOutput struct{ *pulumi.OutputState }

func (LookupAutonomousContainerDatabaseDataguardAssociationResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupAutonomousContainerDatabaseDataguardAssociationResult)(nil)).Elem()
}

func (o LookupAutonomousContainerDatabaseDataguardAssociationResultOutput) ToLookupAutonomousContainerDatabaseDataguardAssociationResultOutput() LookupAutonomousContainerDatabaseDataguardAssociationResultOutput {
	return o
}

func (o LookupAutonomousContainerDatabaseDataguardAssociationResultOutput) ToLookupAutonomousContainerDatabaseDataguardAssociationResultOutputWithContext(ctx context.Context) LookupAutonomousContainerDatabaseDataguardAssociationResultOutput {
	return o
}

// The lag time between updates to the primary Autonomous Container Database and application of the redo data on the standby Autonomous Container Database, as computed by the reporting database.  Example: `9 seconds`
func (o LookupAutonomousContainerDatabaseDataguardAssociationResultOutput) ApplyLag() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousContainerDatabaseDataguardAssociationResult) string { return v.ApplyLag }).(pulumi.StringOutput)
}

// The rate at which redo logs are synchronized between the associated Autonomous Container Databases.  Example: `180 Mb per second`
func (o LookupAutonomousContainerDatabaseDataguardAssociationResultOutput) ApplyRate() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousContainerDatabaseDataguardAssociationResult) string { return v.ApplyRate }).(pulumi.StringOutput)
}

func (o LookupAutonomousContainerDatabaseDataguardAssociationResultOutput) AutonomousContainerDatabaseDataguardAssociationId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousContainerDatabaseDataguardAssociationResult) string {
		return v.AutonomousContainerDatabaseDataguardAssociationId
	}).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Container Database that has a relationship with the peer Autonomous Container Database.
func (o LookupAutonomousContainerDatabaseDataguardAssociationResultOutput) AutonomousContainerDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousContainerDatabaseDataguardAssociationResult) string {
		return v.AutonomousContainerDatabaseId
	}).(pulumi.StringOutput)
}

// The OCID of the Autonomous Data Guard created for a given Autonomous Container Database.
func (o LookupAutonomousContainerDatabaseDataguardAssociationResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousContainerDatabaseDataguardAssociationResult) string { return v.Id }).(pulumi.StringOutput)
}

// Indicates whether Automatic Failover is enabled for Autonomous Container Database Dataguard Association
func (o LookupAutonomousContainerDatabaseDataguardAssociationResultOutput) IsAutomaticFailoverEnabled() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupAutonomousContainerDatabaseDataguardAssociationResult) bool {
		return v.IsAutomaticFailoverEnabled
	}).(pulumi.BoolOutput)
}

// Additional information about the current lifecycleState, if available.
func (o LookupAutonomousContainerDatabaseDataguardAssociationResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousContainerDatabaseDataguardAssociationResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The OCID of the peer Autonomous Container Database-Autonomous Data Guard association.
func (o LookupAutonomousContainerDatabaseDataguardAssociationResultOutput) PeerAutonomousContainerDatabaseDataguardAssociationId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousContainerDatabaseDataguardAssociationResult) string {
		return v.PeerAutonomousContainerDatabaseDataguardAssociationId
	}).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer Autonomous Container Database.
func (o LookupAutonomousContainerDatabaseDataguardAssociationResultOutput) PeerAutonomousContainerDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousContainerDatabaseDataguardAssociationResult) string {
		return v.PeerAutonomousContainerDatabaseId
	}).(pulumi.StringOutput)
}

// The current state of Autonomous Data Guard.
func (o LookupAutonomousContainerDatabaseDataguardAssociationResultOutput) PeerLifecycleState() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousContainerDatabaseDataguardAssociationResult) string {
		return v.PeerLifecycleState
	}).(pulumi.StringOutput)
}

// The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled.
func (o LookupAutonomousContainerDatabaseDataguardAssociationResultOutput) PeerRole() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousContainerDatabaseDataguardAssociationResult) string { return v.PeerRole }).(pulumi.StringOutput)
}

// The protection mode of this Autonomous Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
func (o LookupAutonomousContainerDatabaseDataguardAssociationResultOutput) ProtectionMode() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousContainerDatabaseDataguardAssociationResult) string { return v.ProtectionMode }).(pulumi.StringOutput)
}

// The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled.
func (o LookupAutonomousContainerDatabaseDataguardAssociationResultOutput) Role() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousContainerDatabaseDataguardAssociationResult) string { return v.Role }).(pulumi.StringOutput)
}

// The current state of Autonomous Data Guard.
func (o LookupAutonomousContainerDatabaseDataguardAssociationResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousContainerDatabaseDataguardAssociationResult) string { return v.State }).(pulumi.StringOutput)
}

// The date and time the Autonomous DataGuard association was created.
func (o LookupAutonomousContainerDatabaseDataguardAssociationResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousContainerDatabaseDataguardAssociationResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time when the last role change action happened.
func (o LookupAutonomousContainerDatabaseDataguardAssociationResultOutput) TimeLastRoleChanged() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousContainerDatabaseDataguardAssociationResult) string {
		return v.TimeLastRoleChanged
	}).(pulumi.StringOutput)
}

// The date and time of the last update to the apply lag, apply rate, and transport lag values.
func (o LookupAutonomousContainerDatabaseDataguardAssociationResultOutput) TimeLastSynced() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousContainerDatabaseDataguardAssociationResult) string { return v.TimeLastSynced }).(pulumi.StringOutput)
}

// The approximate number of seconds of redo data not yet available on the standby Autonomous Container Database, as computed by the reporting database.  Example: `7 seconds`
func (o LookupAutonomousContainerDatabaseDataguardAssociationResultOutput) TransportLag() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAutonomousContainerDatabaseDataguardAssociationResult) string { return v.TransportLag }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupAutonomousContainerDatabaseDataguardAssociationResultOutput{})
}