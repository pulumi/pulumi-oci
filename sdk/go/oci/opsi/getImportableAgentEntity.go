// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package opsi

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Importable Agent Entity resource in Oracle Cloud Infrastructure Opsi service.
//
// Gets a list of agent entities available to add a new hostInsight.  An agent entity is "available"
// and will be shown if all the following conditions are true:
//  1. The agent OCID is not already being used for an existing hostInsight.
//  2. The agent availabilityStatus = 'ACTIVE'
//  3. The agent lifecycleState = 'ACTIVE'
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/opsi"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := opsi.GetImportableAgentEntity(ctx, &opsi.GetImportableAgentEntityArgs{
//				CompartmentId: compartmentId,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetImportableAgentEntity(ctx *pulumi.Context, args *GetImportableAgentEntityArgs, opts ...pulumi.InvokeOption) (*GetImportableAgentEntityResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetImportableAgentEntityResult
	err := ctx.Invoke("oci:Opsi/getImportableAgentEntity:getImportableAgentEntity", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getImportableAgentEntity.
type GetImportableAgentEntityArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
}

// A collection of values returned by getImportableAgentEntity.
type GetImportableAgentEntityResult struct {
	CompartmentId string `pulumi:"compartmentId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Array of importable agent entity objects.
	Items []GetImportableAgentEntityItem `pulumi:"items"`
}

func GetImportableAgentEntityOutput(ctx *pulumi.Context, args GetImportableAgentEntityOutputArgs, opts ...pulumi.InvokeOption) GetImportableAgentEntityResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetImportableAgentEntityResultOutput, error) {
			args := v.(GetImportableAgentEntityArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Opsi/getImportableAgentEntity:getImportableAgentEntity", args, GetImportableAgentEntityResultOutput{}, options).(GetImportableAgentEntityResultOutput), nil
		}).(GetImportableAgentEntityResultOutput)
}

// A collection of arguments for invoking getImportableAgentEntity.
type GetImportableAgentEntityOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
}

func (GetImportableAgentEntityOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetImportableAgentEntityArgs)(nil)).Elem()
}

// A collection of values returned by getImportableAgentEntity.
type GetImportableAgentEntityResultOutput struct{ *pulumi.OutputState }

func (GetImportableAgentEntityResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetImportableAgentEntityResult)(nil)).Elem()
}

func (o GetImportableAgentEntityResultOutput) ToGetImportableAgentEntityResultOutput() GetImportableAgentEntityResultOutput {
	return o
}

func (o GetImportableAgentEntityResultOutput) ToGetImportableAgentEntityResultOutputWithContext(ctx context.Context) GetImportableAgentEntityResultOutput {
	return o
}

func (o GetImportableAgentEntityResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetImportableAgentEntityResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetImportableAgentEntityResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetImportableAgentEntityResult) string { return v.Id }).(pulumi.StringOutput)
}

// Array of importable agent entity objects.
func (o GetImportableAgentEntityResultOutput) Items() GetImportableAgentEntityItemArrayOutput {
	return o.ApplyT(func(v GetImportableAgentEntityResult) []GetImportableAgentEntityItem { return v.Items }).(GetImportableAgentEntityItemArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetImportableAgentEntityResultOutput{})
}
