// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package mysql

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Replicas in Oracle Cloud Infrastructure MySQL Database service.
//
// Lists all the read replicas that match the specified filters.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Mysql"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Mysql.GetReplicas(ctx, &mysql.GetReplicasArgs{
//				CompartmentId: _var.Compartment_id,
//				DbSystemId:    pulumi.StringRef(oci_mysql_mysql_db_system.Test_mysql_db_system.Id),
//				DisplayName:   pulumi.StringRef(_var.Replica_display_name),
//				ReplicaId:     pulumi.StringRef(oci_mysql_replica.Test_replica.Id),
//				State:         pulumi.StringRef(_var.Replica_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetReplicas(ctx *pulumi.Context, args *GetReplicasArgs, opts ...pulumi.InvokeOption) (*GetReplicasResult, error) {
	var rv GetReplicasResult
	err := ctx.Invoke("oci:Mysql/getReplicas:getReplicas", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getReplicas.
type GetReplicasArgs struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string `pulumi:"compartmentId"`
	// The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbSystemId *string `pulumi:"dbSystemId"`
	// A filter to return only the resource matching the given display name exactly.
	DisplayName *string             `pulumi:"displayName"`
	Filters     []GetReplicasFilter `pulumi:"filters"`
	// The read replica [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	ReplicaId *string `pulumi:"replicaId"`
	// The LifecycleState of the read replica.
	State *string `pulumi:"state"`
}

// A collection of values returned by getReplicas.
type GetReplicasResult struct {
	// The OCID of the compartment that contains the read replica.
	CompartmentId string `pulumi:"compartmentId"`
	// The OCID of the DB System the read replica is associated with.
	DbSystemId *string `pulumi:"dbSystemId"`
	// The user-friendly name for the read replica. It does not have to be unique.
	DisplayName *string             `pulumi:"displayName"`
	Filters     []GetReplicasFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id        string  `pulumi:"id"`
	ReplicaId *string `pulumi:"replicaId"`
	// The list of replicas.
	Replicas []GetReplicasReplica `pulumi:"replicas"`
	// The state of the read replica.
	State *string `pulumi:"state"`
}

func GetReplicasOutput(ctx *pulumi.Context, args GetReplicasOutputArgs, opts ...pulumi.InvokeOption) GetReplicasResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetReplicasResult, error) {
			args := v.(GetReplicasArgs)
			r, err := GetReplicas(ctx, &args, opts...)
			var s GetReplicasResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetReplicasResultOutput)
}

// A collection of arguments for invoking getReplicas.
type GetReplicasOutputArgs struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbSystemId pulumi.StringPtrInput `pulumi:"dbSystemId"`
	// A filter to return only the resource matching the given display name exactly.
	DisplayName pulumi.StringPtrInput       `pulumi:"displayName"`
	Filters     GetReplicasFilterArrayInput `pulumi:"filters"`
	// The read replica [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	ReplicaId pulumi.StringPtrInput `pulumi:"replicaId"`
	// The LifecycleState of the read replica.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetReplicasOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetReplicasArgs)(nil)).Elem()
}

// A collection of values returned by getReplicas.
type GetReplicasResultOutput struct{ *pulumi.OutputState }

func (GetReplicasResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetReplicasResult)(nil)).Elem()
}

func (o GetReplicasResultOutput) ToGetReplicasResultOutput() GetReplicasResultOutput {
	return o
}

func (o GetReplicasResultOutput) ToGetReplicasResultOutputWithContext(ctx context.Context) GetReplicasResultOutput {
	return o
}

// The OCID of the compartment that contains the read replica.
func (o GetReplicasResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetReplicasResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The OCID of the DB System the read replica is associated with.
func (o GetReplicasResultOutput) DbSystemId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetReplicasResult) *string { return v.DbSystemId }).(pulumi.StringPtrOutput)
}

// The user-friendly name for the read replica. It does not have to be unique.
func (o GetReplicasResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetReplicasResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetReplicasResultOutput) Filters() GetReplicasFilterArrayOutput {
	return o.ApplyT(func(v GetReplicasResult) []GetReplicasFilter { return v.Filters }).(GetReplicasFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetReplicasResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetReplicasResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetReplicasResultOutput) ReplicaId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetReplicasResult) *string { return v.ReplicaId }).(pulumi.StringPtrOutput)
}

// The list of replicas.
func (o GetReplicasResultOutput) Replicas() GetReplicasReplicaArrayOutput {
	return o.ApplyT(func(v GetReplicasResult) []GetReplicasReplica { return v.Replicas }).(GetReplicasReplicaArrayOutput)
}

// The state of the read replica.
func (o GetReplicasResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetReplicasResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetReplicasResultOutput{})
}