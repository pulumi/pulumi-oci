// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package opsi

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Importable Compute Entity resource in Oracle Cloud Infrastructure Opsi service.
//
// Gets a list of available compute intances running cloud agent to add a new hostInsight.  An Compute entity is "available"
// and will be shown if all the following conditions are true:
//  1. Compute is running OCA
//  2. Oracle Cloud Infrastructure Management Agent is not enabled or If Oracle Cloud Infrastructure Management Agent is enabled
//     2.1 The agent OCID is not already being used for an existing hostInsight.
//     2.2 The agent availabilityStatus = 'ACTIVE'
//     2.3 The agent lifecycleState = 'ACTIVE'
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Opsi"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Opsi.GetImportableComputeEntity(ctx, &opsi.GetImportableComputeEntityArgs{
//				CompartmentId: _var.Compartment_id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetImportableComputeEntity(ctx *pulumi.Context, args *GetImportableComputeEntityArgs, opts ...pulumi.InvokeOption) (*GetImportableComputeEntityResult, error) {
	var rv GetImportableComputeEntityResult
	err := ctx.Invoke("oci:Opsi/getImportableComputeEntity:getImportableComputeEntity", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getImportableComputeEntity.
type GetImportableComputeEntityArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
}

// A collection of values returned by getImportableComputeEntity.
type GetImportableComputeEntityResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Array of importable compute entity objects.
	Items []GetImportableComputeEntityItem `pulumi:"items"`
}

func GetImportableComputeEntityOutput(ctx *pulumi.Context, args GetImportableComputeEntityOutputArgs, opts ...pulumi.InvokeOption) GetImportableComputeEntityResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetImportableComputeEntityResult, error) {
			args := v.(GetImportableComputeEntityArgs)
			r, err := GetImportableComputeEntity(ctx, &args, opts...)
			var s GetImportableComputeEntityResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetImportableComputeEntityResultOutput)
}

// A collection of arguments for invoking getImportableComputeEntity.
type GetImportableComputeEntityOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
}

func (GetImportableComputeEntityOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetImportableComputeEntityArgs)(nil)).Elem()
}

// A collection of values returned by getImportableComputeEntity.
type GetImportableComputeEntityResultOutput struct{ *pulumi.OutputState }

func (GetImportableComputeEntityResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetImportableComputeEntityResult)(nil)).Elem()
}

func (o GetImportableComputeEntityResultOutput) ToGetImportableComputeEntityResultOutput() GetImportableComputeEntityResultOutput {
	return o
}

func (o GetImportableComputeEntityResultOutput) ToGetImportableComputeEntityResultOutputWithContext(ctx context.Context) GetImportableComputeEntityResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o GetImportableComputeEntityResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetImportableComputeEntityResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetImportableComputeEntityResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetImportableComputeEntityResult) string { return v.Id }).(pulumi.StringOutput)
}

// Array of importable compute entity objects.
func (o GetImportableComputeEntityResultOutput) Items() GetImportableComputeEntityItemArrayOutput {
	return o.ApplyT(func(v GetImportableComputeEntityResult) []GetImportableComputeEntityItem { return v.Items }).(GetImportableComputeEntityItemArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetImportableComputeEntityResultOutput{})
}