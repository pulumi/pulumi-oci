// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package apmsynthetics

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Public Vantage Point resource in Oracle Cloud Infrastructure Apm Synthetics service.
//
// Returns a list of public vantage points.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/ApmSynthetics"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := ApmSynthetics.GetVantagePoint(ctx, &apmsynthetics.GetVantagePointArgs{
//				ApmDomainId: oci_apm_synthetics_apm_domain.Test_apm_domain.Id,
//				DisplayName: pulumi.StringRef(_var.Public_vantage_point_display_name),
//				Name:        pulumi.StringRef(_var.Public_vantage_point_name),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetVantagePoint(ctx *pulumi.Context, args *GetVantagePointArgs, opts ...pulumi.InvokeOption) (*GetVantagePointResult, error) {
	var rv GetVantagePointResult
	err := ctx.Invoke("oci:ApmSynthetics/getVantagePoint:getVantagePoint", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getVantagePoint.
type GetVantagePointArgs struct {
	// The APM domain ID the request is intended for.
	ApmDomainId string `pulumi:"apmDomainId"`
	// A filter to return only the resources that match the entire display name.
	DisplayName *string `pulumi:"displayName"`
	// A filter to return only the resources that match the entire name.
	Name *string `pulumi:"name"`
}

// A collection of values returned by getVantagePoint.
type GetVantagePointResult struct {
	ApmDomainId string `pulumi:"apmDomainId"`
	// Unique name that can be edited. The name should not contain any confidential information.
	DisplayName *string `pulumi:"displayName"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// List of PublicVantagePointSummary items.
	Items []GetVantagePointItem `pulumi:"items"`
	// Unique permanent name of the vantage point.
	Name *string `pulumi:"name"`
}

func GetVantagePointOutput(ctx *pulumi.Context, args GetVantagePointOutputArgs, opts ...pulumi.InvokeOption) GetVantagePointResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetVantagePointResult, error) {
			args := v.(GetVantagePointArgs)
			r, err := GetVantagePoint(ctx, &args, opts...)
			var s GetVantagePointResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetVantagePointResultOutput)
}

// A collection of arguments for invoking getVantagePoint.
type GetVantagePointOutputArgs struct {
	// The APM domain ID the request is intended for.
	ApmDomainId pulumi.StringInput `pulumi:"apmDomainId"`
	// A filter to return only the resources that match the entire display name.
	DisplayName pulumi.StringPtrInput `pulumi:"displayName"`
	// A filter to return only the resources that match the entire name.
	Name pulumi.StringPtrInput `pulumi:"name"`
}

func (GetVantagePointOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetVantagePointArgs)(nil)).Elem()
}

// A collection of values returned by getVantagePoint.
type GetVantagePointResultOutput struct{ *pulumi.OutputState }

func (GetVantagePointResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetVantagePointResult)(nil)).Elem()
}

func (o GetVantagePointResultOutput) ToGetVantagePointResultOutput() GetVantagePointResultOutput {
	return o
}

func (o GetVantagePointResultOutput) ToGetVantagePointResultOutputWithContext(ctx context.Context) GetVantagePointResultOutput {
	return o
}

func (o GetVantagePointResultOutput) ApmDomainId() pulumi.StringOutput {
	return o.ApplyT(func(v GetVantagePointResult) string { return v.ApmDomainId }).(pulumi.StringOutput)
}

// Unique name that can be edited. The name should not contain any confidential information.
func (o GetVantagePointResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetVantagePointResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetVantagePointResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetVantagePointResult) string { return v.Id }).(pulumi.StringOutput)
}

// List of PublicVantagePointSummary items.
func (o GetVantagePointResultOutput) Items() GetVantagePointItemArrayOutput {
	return o.ApplyT(func(v GetVantagePointResult) []GetVantagePointItem { return v.Items }).(GetVantagePointItemArrayOutput)
}

// Unique permanent name of the vantage point.
func (o GetVantagePointResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetVantagePointResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetVantagePointResultOutput{})
}