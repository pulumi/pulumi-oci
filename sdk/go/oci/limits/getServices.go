// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package limits

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Services in Oracle Cloud Infrastructure Limits service.
//
// Returns the list of supported services.
// This includes the programmatic service name, along with the friendly service name.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/Limits"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := Limits.GetServices(ctx, &limits.GetServicesArgs{
// 			CompartmentId: _var.Tenancy_ocid,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetServices(ctx *pulumi.Context, args *GetServicesArgs, opts ...pulumi.InvokeOption) (*GetServicesResult, error) {
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
}

// A collection of values returned by getServices.
type GetServicesResult struct {
	CompartmentId string              `pulumi:"compartmentId"`
	Filters       []GetServicesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of services.
	Services []GetServicesService `pulumi:"services"`
}

func GetServicesOutput(ctx *pulumi.Context, args GetServicesOutputArgs, opts ...pulumi.InvokeOption) GetServicesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetServicesResult, error) {
			args := v.(GetServicesArgs)
			r, err := GetServices(ctx, &args, opts...)
			var s GetServicesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetServicesResultOutput)
}

// A collection of arguments for invoking getServices.
type GetServicesOutputArgs struct {
	// The OCID of the parent compartment (remember that the tenancy is simply the root compartment).
	CompartmentId pulumi.StringInput          `pulumi:"compartmentId"`
	Filters       GetServicesFilterArrayInput `pulumi:"filters"`
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

func init() {
	pulumi.RegisterOutputType(GetServicesResultOutput{})
}
