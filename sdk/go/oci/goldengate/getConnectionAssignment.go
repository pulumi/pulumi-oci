// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package goldengate

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Connection Assignment resource in Oracle Cloud Infrastructure Golden Gate service.
//
// Retrieves a Connection Assignment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/GoldenGate"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := GoldenGate.GetConnectionAssignment(ctx, &goldengate.GetConnectionAssignmentArgs{
//				ConnectionAssignmentId: oci_golden_gate_connection_assignment.Test_connection_assignment.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupConnectionAssignment(ctx *pulumi.Context, args *LookupConnectionAssignmentArgs, opts ...pulumi.InvokeOption) (*LookupConnectionAssignmentResult, error) {
	var rv LookupConnectionAssignmentResult
	err := ctx.Invoke("oci:GoldenGate/getConnectionAssignment:getConnectionAssignment", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getConnectionAssignment.
type LookupConnectionAssignmentArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Connection Assignment.
	ConnectionAssignmentId string `pulumi:"connectionAssignmentId"`
}

// A collection of values returned by getConnectionAssignment.
type LookupConnectionAssignmentResult struct {
	// Credential store alias.
	AliasName string `pulumi:"aliasName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
	CompartmentId          string `pulumi:"compartmentId"`
	ConnectionAssignmentId string `pulumi:"connectionAssignmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the connection being referenced.
	ConnectionId string `pulumi:"connectionId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment being referenced.
	DeploymentId string `pulumi:"deploymentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the connection assignment being referenced.
	Id string `pulumi:"id"`
	// Possible lifecycle states for connection assignments.
	State string `pulumi:"state"`
	// The time the resource was created. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
	TimeCreated string `pulumi:"timeCreated"`
	// The time the resource was last updated. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupConnectionAssignmentOutput(ctx *pulumi.Context, args LookupConnectionAssignmentOutputArgs, opts ...pulumi.InvokeOption) LookupConnectionAssignmentResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupConnectionAssignmentResult, error) {
			args := v.(LookupConnectionAssignmentArgs)
			r, err := LookupConnectionAssignment(ctx, &args, opts...)
			var s LookupConnectionAssignmentResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupConnectionAssignmentResultOutput)
}

// A collection of arguments for invoking getConnectionAssignment.
type LookupConnectionAssignmentOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Connection Assignment.
	ConnectionAssignmentId pulumi.StringInput `pulumi:"connectionAssignmentId"`
}

func (LookupConnectionAssignmentOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupConnectionAssignmentArgs)(nil)).Elem()
}

// A collection of values returned by getConnectionAssignment.
type LookupConnectionAssignmentResultOutput struct{ *pulumi.OutputState }

func (LookupConnectionAssignmentResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupConnectionAssignmentResult)(nil)).Elem()
}

func (o LookupConnectionAssignmentResultOutput) ToLookupConnectionAssignmentResultOutput() LookupConnectionAssignmentResultOutput {
	return o
}

func (o LookupConnectionAssignmentResultOutput) ToLookupConnectionAssignmentResultOutputWithContext(ctx context.Context) LookupConnectionAssignmentResultOutput {
	return o
}

// Credential store alias.
func (o LookupConnectionAssignmentResultOutput) AliasName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionAssignmentResult) string { return v.AliasName }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
func (o LookupConnectionAssignmentResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionAssignmentResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o LookupConnectionAssignmentResultOutput) ConnectionAssignmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionAssignmentResult) string { return v.ConnectionAssignmentId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the connection being referenced.
func (o LookupConnectionAssignmentResultOutput) ConnectionId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionAssignmentResult) string { return v.ConnectionId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment being referenced.
func (o LookupConnectionAssignmentResultOutput) DeploymentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionAssignmentResult) string { return v.DeploymentId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the connection assignment being referenced.
func (o LookupConnectionAssignmentResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionAssignmentResult) string { return v.Id }).(pulumi.StringOutput)
}

// Possible lifecycle states for connection assignments.
func (o LookupConnectionAssignmentResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionAssignmentResult) string { return v.State }).(pulumi.StringOutput)
}

// The time the resource was created. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
func (o LookupConnectionAssignmentResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionAssignmentResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the resource was last updated. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
func (o LookupConnectionAssignmentResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupConnectionAssignmentResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupConnectionAssignmentResultOutput{})
}