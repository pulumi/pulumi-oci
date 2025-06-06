// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package apmsynthetics

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Public Vantage Points in Oracle Cloud Infrastructure APM Availability Monitoring service (aka APM Synthetics Service).
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
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/apmsynthetics"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := apmsynthetics.GetVantagePoints(ctx, &apmsynthetics.GetVantagePointsArgs{
//				ApmDomainId: testApmDomain.Id,
//				DisplayName: pulumi.StringRef(publicVantagePointDisplayName),
//				Name:        pulumi.StringRef(publicVantagePointName),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetVantagePoints(ctx *pulumi.Context, args *GetVantagePointsArgs, opts ...pulumi.InvokeOption) (*GetVantagePointsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetVantagePointsResult
	err := ctx.Invoke("oci:ApmSynthetics/getVantagePoints:getVantagePoints", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getVantagePoints.
type GetVantagePointsArgs struct {
	// The APM domain ID the request is intended for.
	ApmDomainId string `pulumi:"apmDomainId"`
	// A filter to return only the resources that match the entire display name.
	DisplayName *string                  `pulumi:"displayName"`
	Filters     []GetVantagePointsFilter `pulumi:"filters"`
	// A filter to return only the resources that match the entire name.
	Name *string `pulumi:"name"`
}

// A collection of values returned by getVantagePoints.
type GetVantagePointsResult struct {
	ApmDomainId string `pulumi:"apmDomainId"`
	// Unique name that can be edited. The name should not contain any confidential information.
	DisplayName *string                  `pulumi:"displayName"`
	Filters     []GetVantagePointsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Unique permanent name of the vantage point.
	Name *string `pulumi:"name"`
	// The list of public_vantage_point_collection.
	PublicVantagePointCollections []GetVantagePointsPublicVantagePointCollection `pulumi:"publicVantagePointCollections"`
}

func GetVantagePointsOutput(ctx *pulumi.Context, args GetVantagePointsOutputArgs, opts ...pulumi.InvokeOption) GetVantagePointsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetVantagePointsResultOutput, error) {
			args := v.(GetVantagePointsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:ApmSynthetics/getVantagePoints:getVantagePoints", args, GetVantagePointsResultOutput{}, options).(GetVantagePointsResultOutput), nil
		}).(GetVantagePointsResultOutput)
}

// A collection of arguments for invoking getVantagePoints.
type GetVantagePointsOutputArgs struct {
	// The APM domain ID the request is intended for.
	ApmDomainId pulumi.StringInput `pulumi:"apmDomainId"`
	// A filter to return only the resources that match the entire display name.
	DisplayName pulumi.StringPtrInput            `pulumi:"displayName"`
	Filters     GetVantagePointsFilterArrayInput `pulumi:"filters"`
	// A filter to return only the resources that match the entire name.
	Name pulumi.StringPtrInput `pulumi:"name"`
}

func (GetVantagePointsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetVantagePointsArgs)(nil)).Elem()
}

// A collection of values returned by getVantagePoints.
type GetVantagePointsResultOutput struct{ *pulumi.OutputState }

func (GetVantagePointsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetVantagePointsResult)(nil)).Elem()
}

func (o GetVantagePointsResultOutput) ToGetVantagePointsResultOutput() GetVantagePointsResultOutput {
	return o
}

func (o GetVantagePointsResultOutput) ToGetVantagePointsResultOutputWithContext(ctx context.Context) GetVantagePointsResultOutput {
	return o
}

func (o GetVantagePointsResultOutput) ApmDomainId() pulumi.StringOutput {
	return o.ApplyT(func(v GetVantagePointsResult) string { return v.ApmDomainId }).(pulumi.StringOutput)
}

// Unique name that can be edited. The name should not contain any confidential information.
func (o GetVantagePointsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetVantagePointsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetVantagePointsResultOutput) Filters() GetVantagePointsFilterArrayOutput {
	return o.ApplyT(func(v GetVantagePointsResult) []GetVantagePointsFilter { return v.Filters }).(GetVantagePointsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetVantagePointsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetVantagePointsResult) string { return v.Id }).(pulumi.StringOutput)
}

// Unique permanent name of the vantage point.
func (o GetVantagePointsResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetVantagePointsResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The list of public_vantage_point_collection.
func (o GetVantagePointsResultOutput) PublicVantagePointCollections() GetVantagePointsPublicVantagePointCollectionArrayOutput {
	return o.ApplyT(func(v GetVantagePointsResult) []GetVantagePointsPublicVantagePointCollection {
		return v.PublicVantagePointCollections
	}).(GetVantagePointsPublicVantagePointCollectionArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetVantagePointsResultOutput{})
}
