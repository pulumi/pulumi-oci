// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Byoasns in Oracle Cloud Infrastructure Core service.
//
// Lists the `Byoasn` resources in the specified compartment.
// You can filter the list using query parameters.
func GetByoasns(ctx *pulumi.Context, args *GetByoasnsArgs, opts ...pulumi.InvokeOption) (*GetByoasnsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetByoasnsResult
	err := ctx.Invoke("oci:Core/getByoasns:getByoasns", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getByoasns.
type GetByoasnsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string             `pulumi:"compartmentId"`
	Filters       []GetByoasnsFilter `pulumi:"filters"`
}

// A collection of values returned by getByoasns.
type GetByoasnsResult struct {
	// The list of byoasn_collection.
	ByoasnCollections []GetByoasnsByoasnCollection `pulumi:"byoasnCollections"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the `Byoasn` resource.
	CompartmentId string             `pulumi:"compartmentId"`
	Filters       []GetByoasnsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}

func GetByoasnsOutput(ctx *pulumi.Context, args GetByoasnsOutputArgs, opts ...pulumi.InvokeOption) GetByoasnsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetByoasnsResultOutput, error) {
			args := v.(GetByoasnsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Core/getByoasns:getByoasns", args, GetByoasnsResultOutput{}, options).(GetByoasnsResultOutput), nil
		}).(GetByoasnsResultOutput)
}

// A collection of arguments for invoking getByoasns.
type GetByoasnsOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput         `pulumi:"compartmentId"`
	Filters       GetByoasnsFilterArrayInput `pulumi:"filters"`
}

func (GetByoasnsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetByoasnsArgs)(nil)).Elem()
}

// A collection of values returned by getByoasns.
type GetByoasnsResultOutput struct{ *pulumi.OutputState }

func (GetByoasnsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetByoasnsResult)(nil)).Elem()
}

func (o GetByoasnsResultOutput) ToGetByoasnsResultOutput() GetByoasnsResultOutput {
	return o
}

func (o GetByoasnsResultOutput) ToGetByoasnsResultOutputWithContext(ctx context.Context) GetByoasnsResultOutput {
	return o
}

// The list of byoasn_collection.
func (o GetByoasnsResultOutput) ByoasnCollections() GetByoasnsByoasnCollectionArrayOutput {
	return o.ApplyT(func(v GetByoasnsResult) []GetByoasnsByoasnCollection { return v.ByoasnCollections }).(GetByoasnsByoasnCollectionArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the `Byoasn` resource.
func (o GetByoasnsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetByoasnsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetByoasnsResultOutput) Filters() GetByoasnsFilterArrayOutput {
	return o.ApplyT(func(v GetByoasnsResult) []GetByoasnsFilter { return v.Filters }).(GetByoasnsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetByoasnsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetByoasnsResult) string { return v.Id }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetByoasnsResultOutput{})
}
