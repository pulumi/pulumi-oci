// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Autonomous Database Dataguard Association resource in Oracle Cloud Infrastructure Database service.
//
// Gets an Autonomous Database dataguard assocation for the specified Autonomous Database.
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
//			_, err := Database.GetAutonomousDatabaseDataguardAssociation(ctx, &database.GetAutonomousDatabaseDataguardAssociationArgs{
//				AutonomousDatabaseDataguardAssociationId: oci_database_autonomous_database_dataguard_association.Test_autonomous_database_dataguard_association.Id,
//				AutonomousDatabaseId:                     oci_database_autonomous_database.Test_autonomous_database.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetAutonomousDatabaseDataguardAssociation(ctx *pulumi.Context, args *GetAutonomousDatabaseDataguardAssociationArgs, opts ...pulumi.InvokeOption) (*GetAutonomousDatabaseDataguardAssociationResult, error) {
	var rv GetAutonomousDatabaseDataguardAssociationResult
	err := ctx.Invoke("oci:Database/getAutonomousDatabaseDataguardAssociation:getAutonomousDatabaseDataguardAssociation", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAutonomousDatabaseDataguardAssociation.
type GetAutonomousDatabaseDataguardAssociationArgs struct {
	// The Autonomous Database Dataguard Association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousDatabaseDataguardAssociationId string `pulumi:"autonomousDatabaseDataguardAssociationId"`
	// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousDatabaseId string `pulumi:"autonomousDatabaseId"`
}

// A collection of values returned by getAutonomousDatabaseDataguardAssociation.
type GetAutonomousDatabaseDataguardAssociationResult struct {
	// The lag time between updates to the primary database and application of the redo data on the standby database, as computed by the reporting database.  Example: `9 seconds`
	ApplyLag string `pulumi:"applyLag"`
	// The rate at which redo logs are synced between the associated databases.  Example: `180 Mb per second`
	ApplyRate                                string `pulumi:"applyRate"`
	AutonomousDatabaseDataguardAssociationId string `pulumi:"autonomousDatabaseDataguardAssociationId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database that has a relationship with the peer Autonomous Database.
	AutonomousDatabaseId string `pulumi:"autonomousDatabaseId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Additional information about the current lifecycleState, if available.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer Autonomous Database.
	PeerAutonomousDatabaseId string `pulumi:"peerAutonomousDatabaseId"`
	// The current state of the Autonomous Dataguard.
	PeerAutonomousDatabaseLifeCycleState string `pulumi:"peerAutonomousDatabaseLifeCycleState"`
	// The role of the Autonomous Dataguard enabled Autonomous Container Database.
	PeerRole string `pulumi:"peerRole"`
	// The protection mode of this Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
	ProtectionMode string `pulumi:"protectionMode"`
	// The role of the Autonomous Dataguard enabled Autonomous Container Database.
	Role string `pulumi:"role"`
	// The current state of the Autonomous Dataguard.
	State string `pulumi:"state"`
	// The date and time the Data Guard association was created.
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time when the last role change action happened.
	TimeLastRoleChanged string `pulumi:"timeLastRoleChanged"`
}

func GetAutonomousDatabaseDataguardAssociationOutput(ctx *pulumi.Context, args GetAutonomousDatabaseDataguardAssociationOutputArgs, opts ...pulumi.InvokeOption) GetAutonomousDatabaseDataguardAssociationResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetAutonomousDatabaseDataguardAssociationResult, error) {
			args := v.(GetAutonomousDatabaseDataguardAssociationArgs)
			r, err := GetAutonomousDatabaseDataguardAssociation(ctx, &args, opts...)
			var s GetAutonomousDatabaseDataguardAssociationResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetAutonomousDatabaseDataguardAssociationResultOutput)
}

// A collection of arguments for invoking getAutonomousDatabaseDataguardAssociation.
type GetAutonomousDatabaseDataguardAssociationOutputArgs struct {
	// The Autonomous Database Dataguard Association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousDatabaseDataguardAssociationId pulumi.StringInput `pulumi:"autonomousDatabaseDataguardAssociationId"`
	// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousDatabaseId pulumi.StringInput `pulumi:"autonomousDatabaseId"`
}

func (GetAutonomousDatabaseDataguardAssociationOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAutonomousDatabaseDataguardAssociationArgs)(nil)).Elem()
}

// A collection of values returned by getAutonomousDatabaseDataguardAssociation.
type GetAutonomousDatabaseDataguardAssociationResultOutput struct{ *pulumi.OutputState }

func (GetAutonomousDatabaseDataguardAssociationResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAutonomousDatabaseDataguardAssociationResult)(nil)).Elem()
}

func (o GetAutonomousDatabaseDataguardAssociationResultOutput) ToGetAutonomousDatabaseDataguardAssociationResultOutput() GetAutonomousDatabaseDataguardAssociationResultOutput {
	return o
}

func (o GetAutonomousDatabaseDataguardAssociationResultOutput) ToGetAutonomousDatabaseDataguardAssociationResultOutputWithContext(ctx context.Context) GetAutonomousDatabaseDataguardAssociationResultOutput {
	return o
}

// The lag time between updates to the primary database and application of the redo data on the standby database, as computed by the reporting database.  Example: `9 seconds`
func (o GetAutonomousDatabaseDataguardAssociationResultOutput) ApplyLag() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutonomousDatabaseDataguardAssociationResult) string { return v.ApplyLag }).(pulumi.StringOutput)
}

// The rate at which redo logs are synced between the associated databases.  Example: `180 Mb per second`
func (o GetAutonomousDatabaseDataguardAssociationResultOutput) ApplyRate() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutonomousDatabaseDataguardAssociationResult) string { return v.ApplyRate }).(pulumi.StringOutput)
}

func (o GetAutonomousDatabaseDataguardAssociationResultOutput) AutonomousDatabaseDataguardAssociationId() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutonomousDatabaseDataguardAssociationResult) string {
		return v.AutonomousDatabaseDataguardAssociationId
	}).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database that has a relationship with the peer Autonomous Database.
func (o GetAutonomousDatabaseDataguardAssociationResultOutput) AutonomousDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutonomousDatabaseDataguardAssociationResult) string { return v.AutonomousDatabaseId }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetAutonomousDatabaseDataguardAssociationResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutonomousDatabaseDataguardAssociationResult) string { return v.Id }).(pulumi.StringOutput)
}

// Additional information about the current lifecycleState, if available.
func (o GetAutonomousDatabaseDataguardAssociationResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutonomousDatabaseDataguardAssociationResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer Autonomous Database.
func (o GetAutonomousDatabaseDataguardAssociationResultOutput) PeerAutonomousDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutonomousDatabaseDataguardAssociationResult) string { return v.PeerAutonomousDatabaseId }).(pulumi.StringOutput)
}

// The current state of the Autonomous Dataguard.
func (o GetAutonomousDatabaseDataguardAssociationResultOutput) PeerAutonomousDatabaseLifeCycleState() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutonomousDatabaseDataguardAssociationResult) string {
		return v.PeerAutonomousDatabaseLifeCycleState
	}).(pulumi.StringOutput)
}

// The role of the Autonomous Dataguard enabled Autonomous Container Database.
func (o GetAutonomousDatabaseDataguardAssociationResultOutput) PeerRole() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutonomousDatabaseDataguardAssociationResult) string { return v.PeerRole }).(pulumi.StringOutput)
}

// The protection mode of this Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
func (o GetAutonomousDatabaseDataguardAssociationResultOutput) ProtectionMode() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutonomousDatabaseDataguardAssociationResult) string { return v.ProtectionMode }).(pulumi.StringOutput)
}

// The role of the Autonomous Dataguard enabled Autonomous Container Database.
func (o GetAutonomousDatabaseDataguardAssociationResultOutput) Role() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutonomousDatabaseDataguardAssociationResult) string { return v.Role }).(pulumi.StringOutput)
}

// The current state of the Autonomous Dataguard.
func (o GetAutonomousDatabaseDataguardAssociationResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutonomousDatabaseDataguardAssociationResult) string { return v.State }).(pulumi.StringOutput)
}

// The date and time the Data Guard association was created.
func (o GetAutonomousDatabaseDataguardAssociationResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutonomousDatabaseDataguardAssociationResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time when the last role change action happened.
func (o GetAutonomousDatabaseDataguardAssociationResultOutput) TimeLastRoleChanged() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutonomousDatabaseDataguardAssociationResult) string { return v.TimeLastRoleChanged }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetAutonomousDatabaseDataguardAssociationResultOutput{})
}