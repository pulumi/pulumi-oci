// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package limits

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Quotas in Oracle Cloud Infrastructure Limits service.
//
// Lists all quotas on resources from the given compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/limits"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := limits.GetQuotas(ctx, &limits.GetQuotasArgs{
//				CompartmentId: tenancyOcid,
//				Name:          pulumi.StringRef(quotaName),
//				State:         pulumi.StringRef(quotaState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetQuotas(ctx *pulumi.Context, args *GetQuotasArgs, opts ...pulumi.InvokeOption) (*GetQuotasResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetQuotasResult
	err := ctx.Invoke("oci:Limits/getQuotas:getQuotas", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getQuotas.
type GetQuotasArgs struct {
	// The OCID of the parent compartment (remember that the tenancy is simply the root compartment).
	CompartmentId string            `pulumi:"compartmentId"`
	Filters       []GetQuotasFilter `pulumi:"filters"`
	// name
	Name *string `pulumi:"name"`
	// Filters returned quotas based on the given state.
	State *string `pulumi:"state"`
}

// A collection of values returned by getQuotas.
type GetQuotasResult struct {
	// The OCID of the compartment containing the resource this quota applies to.
	CompartmentId string            `pulumi:"compartmentId"`
	Filters       []GetQuotasFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The name you assign to the quota during creation. The name must be unique across all quotas in the tenancy and cannot be changed.
	Name *string `pulumi:"name"`
	// The list of quotas.
	Quotas []GetQuotasQuota `pulumi:"quotas"`
	// The quota's current state.
	State *string `pulumi:"state"`
}

func GetQuotasOutput(ctx *pulumi.Context, args GetQuotasOutputArgs, opts ...pulumi.InvokeOption) GetQuotasResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetQuotasResultOutput, error) {
			args := v.(GetQuotasArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Limits/getQuotas:getQuotas", args, GetQuotasResultOutput{}, options).(GetQuotasResultOutput), nil
		}).(GetQuotasResultOutput)
}

// A collection of arguments for invoking getQuotas.
type GetQuotasOutputArgs struct {
	// The OCID of the parent compartment (remember that the tenancy is simply the root compartment).
	CompartmentId pulumi.StringInput        `pulumi:"compartmentId"`
	Filters       GetQuotasFilterArrayInput `pulumi:"filters"`
	// name
	Name pulumi.StringPtrInput `pulumi:"name"`
	// Filters returned quotas based on the given state.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetQuotasOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetQuotasArgs)(nil)).Elem()
}

// A collection of values returned by getQuotas.
type GetQuotasResultOutput struct{ *pulumi.OutputState }

func (GetQuotasResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetQuotasResult)(nil)).Elem()
}

func (o GetQuotasResultOutput) ToGetQuotasResultOutput() GetQuotasResultOutput {
	return o
}

func (o GetQuotasResultOutput) ToGetQuotasResultOutputWithContext(ctx context.Context) GetQuotasResultOutput {
	return o
}

// The OCID of the compartment containing the resource this quota applies to.
func (o GetQuotasResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetQuotasResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetQuotasResultOutput) Filters() GetQuotasFilterArrayOutput {
	return o.ApplyT(func(v GetQuotasResult) []GetQuotasFilter { return v.Filters }).(GetQuotasFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetQuotasResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetQuotasResult) string { return v.Id }).(pulumi.StringOutput)
}

// The name you assign to the quota during creation. The name must be unique across all quotas in the tenancy and cannot be changed.
func (o GetQuotasResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetQuotasResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The list of quotas.
func (o GetQuotasResultOutput) Quotas() GetQuotasQuotaArrayOutput {
	return o.ApplyT(func(v GetQuotasResult) []GetQuotasQuota { return v.Quotas }).(GetQuotasQuotaArrayOutput)
}

// The quota's current state.
func (o GetQuotasResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetQuotasResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetQuotasResultOutput{})
}
