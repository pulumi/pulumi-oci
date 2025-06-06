// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package limits

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Services in Oracle Cloud Infrastructure Limits service.
//
// Returns the list of supported services. If subscription ID is provided then only services supported by subscription will be returned.
// This includes the programmatic service name, along with the friendly service name.
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
//			_, err := limits.GetServices(ctx, &limits.GetServicesArgs{
//				CompartmentId:  tenancyOcid,
//				SubscriptionId: pulumi.StringRef(subscriptionOcid),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetServices(ctx *pulumi.Context, args *GetServicesArgs, opts ...pulumi.InvokeOption) (*GetServicesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetServicesResult
	err := ctx.Invoke("oci:Limits/getServices:getServices", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getServices.
type GetServicesArgs struct {
	// The OCID of the parent compartment (remember that the tenancy is simply the root compartment).
	CompartmentId string              `pulumi:"compartmentId"`
	Filters       []GetServicesFilter `pulumi:"filters"`
	// The OCID of the subscription assigned to tenant
	SubscriptionId *string `pulumi:"subscriptionId"`
}

// A collection of values returned by getServices.
type GetServicesResult struct {
	CompartmentId string              `pulumi:"compartmentId"`
	Filters       []GetServicesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of services.
	Services       []GetServicesService `pulumi:"services"`
	SubscriptionId *string              `pulumi:"subscriptionId"`
}

func GetServicesOutput(ctx *pulumi.Context, args GetServicesOutputArgs, opts ...pulumi.InvokeOption) GetServicesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetServicesResultOutput, error) {
			args := v.(GetServicesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Limits/getServices:getServices", args, GetServicesResultOutput{}, options).(GetServicesResultOutput), nil
		}).(GetServicesResultOutput)
}

// A collection of arguments for invoking getServices.
type GetServicesOutputArgs struct {
	// The OCID of the parent compartment (remember that the tenancy is simply the root compartment).
	CompartmentId pulumi.StringInput          `pulumi:"compartmentId"`
	Filters       GetServicesFilterArrayInput `pulumi:"filters"`
	// The OCID of the subscription assigned to tenant
	SubscriptionId pulumi.StringPtrInput `pulumi:"subscriptionId"`
}

func (GetServicesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetServicesArgs)(nil)).Elem()
}

// A collection of values returned by getServices.
type GetServicesResultOutput struct{ *pulumi.OutputState }

func (GetServicesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetServicesResult)(nil)).Elem()
}

func (o GetServicesResultOutput) ToGetServicesResultOutput() GetServicesResultOutput {
	return o
}

func (o GetServicesResultOutput) ToGetServicesResultOutputWithContext(ctx context.Context) GetServicesResultOutput {
	return o
}

func (o GetServicesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetServicesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetServicesResultOutput) Filters() GetServicesFilterArrayOutput {
	return o.ApplyT(func(v GetServicesResult) []GetServicesFilter { return v.Filters }).(GetServicesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetServicesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetServicesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of services.
func (o GetServicesResultOutput) Services() GetServicesServiceArrayOutput {
	return o.ApplyT(func(v GetServicesResult) []GetServicesService { return v.Services }).(GetServicesServiceArrayOutput)
}

func (o GetServicesResultOutput) SubscriptionId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetServicesResult) *string { return v.SubscriptionId }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetServicesResultOutput{})
}
