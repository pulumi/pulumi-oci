// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Fast Connect Provider Services in Oracle Cloud Infrastructure Core service.
//
// Lists the service offerings from supported providers. You need this
// information so you can specify your desired provider and service
// offering when you create a virtual circuit.
//
// For the compartment ID, provide the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of your tenancy (the root compartment).
//
// For more information, see [FastConnect Overview](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/fastconnect.htm).
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Core"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Core.GetFastConnectProviderServices(ctx, &core.GetFastConnectProviderServicesArgs{
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
func GetFastConnectProviderServices(ctx *pulumi.Context, args *GetFastConnectProviderServicesArgs, opts ...pulumi.InvokeOption) (*GetFastConnectProviderServicesResult, error) {
	var rv GetFastConnectProviderServicesResult
	err := ctx.Invoke("oci:Core/getFastConnectProviderServices:getFastConnectProviderServices", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getFastConnectProviderServices.
type GetFastConnectProviderServicesArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string                                 `pulumi:"compartmentId"`
	Filters       []GetFastConnectProviderServicesFilter `pulumi:"filters"`
}

// A collection of values returned by getFastConnectProviderServices.
type GetFastConnectProviderServicesResult struct {
	CompartmentId string `pulumi:"compartmentId"`
	// The list of fast_connect_provider_services.
	FastConnectProviderServices []GetFastConnectProviderServicesFastConnectProviderService `pulumi:"fastConnectProviderServices"`
	Filters                     []GetFastConnectProviderServicesFilter                     `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}

func GetFastConnectProviderServicesOutput(ctx *pulumi.Context, args GetFastConnectProviderServicesOutputArgs, opts ...pulumi.InvokeOption) GetFastConnectProviderServicesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetFastConnectProviderServicesResult, error) {
			args := v.(GetFastConnectProviderServicesArgs)
			r, err := GetFastConnectProviderServices(ctx, &args, opts...)
			var s GetFastConnectProviderServicesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetFastConnectProviderServicesResultOutput)
}

// A collection of arguments for invoking getFastConnectProviderServices.
type GetFastConnectProviderServicesOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput                             `pulumi:"compartmentId"`
	Filters       GetFastConnectProviderServicesFilterArrayInput `pulumi:"filters"`
}

func (GetFastConnectProviderServicesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFastConnectProviderServicesArgs)(nil)).Elem()
}

// A collection of values returned by getFastConnectProviderServices.
type GetFastConnectProviderServicesResultOutput struct{ *pulumi.OutputState }

func (GetFastConnectProviderServicesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFastConnectProviderServicesResult)(nil)).Elem()
}

func (o GetFastConnectProviderServicesResultOutput) ToGetFastConnectProviderServicesResultOutput() GetFastConnectProviderServicesResultOutput {
	return o
}

func (o GetFastConnectProviderServicesResultOutput) ToGetFastConnectProviderServicesResultOutputWithContext(ctx context.Context) GetFastConnectProviderServicesResultOutput {
	return o
}

func (o GetFastConnectProviderServicesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetFastConnectProviderServicesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The list of fast_connect_provider_services.
func (o GetFastConnectProviderServicesResultOutput) FastConnectProviderServices() GetFastConnectProviderServicesFastConnectProviderServiceArrayOutput {
	return o.ApplyT(func(v GetFastConnectProviderServicesResult) []GetFastConnectProviderServicesFastConnectProviderService {
		return v.FastConnectProviderServices
	}).(GetFastConnectProviderServicesFastConnectProviderServiceArrayOutput)
}

func (o GetFastConnectProviderServicesResultOutput) Filters() GetFastConnectProviderServicesFilterArrayOutput {
	return o.ApplyT(func(v GetFastConnectProviderServicesResult) []GetFastConnectProviderServicesFilter { return v.Filters }).(GetFastConnectProviderServicesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetFastConnectProviderServicesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetFastConnectProviderServicesResult) string { return v.Id }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetFastConnectProviderServicesResultOutput{})
}