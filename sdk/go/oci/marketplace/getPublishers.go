// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package marketplace

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Publishers in Oracle Cloud Infrastructure Marketplace service.
//
// Gets the list of all the publishers of listings available in Oracle Cloud Infrastructure Marketplace.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Marketplace"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Marketplace.GetPublishers(ctx, &marketplace.GetPublishersArgs{
//				CompartmentId: pulumi.StringRef(_var.Compartment_id),
//				PublisherId:   pulumi.StringRef(oci_marketplace_publisher.Test_publisher.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetPublishers(ctx *pulumi.Context, args *GetPublishersArgs, opts ...pulumi.InvokeOption) (*GetPublishersResult, error) {
	var rv GetPublishersResult
	err := ctx.Invoke("oci:Marketplace/getPublishers:getPublishers", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getPublishers.
type GetPublishersArgs struct {
	// The unique identifier for the compartment.
	CompartmentId *string               `pulumi:"compartmentId"`
	Filters       []GetPublishersFilter `pulumi:"filters"`
	// Limit results to just this publisher.
	PublisherId *string `pulumi:"publisherId"`
}

// A collection of values returned by getPublishers.
type GetPublishersResult struct {
	CompartmentId *string               `pulumi:"compartmentId"`
	Filters       []GetPublishersFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id          string  `pulumi:"id"`
	PublisherId *string `pulumi:"publisherId"`
	// The list of publishers.
	Publishers []GetPublishersPublisher `pulumi:"publishers"`
}

func GetPublishersOutput(ctx *pulumi.Context, args GetPublishersOutputArgs, opts ...pulumi.InvokeOption) GetPublishersResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetPublishersResult, error) {
			args := v.(GetPublishersArgs)
			r, err := GetPublishers(ctx, &args, opts...)
			var s GetPublishersResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetPublishersResultOutput)
}

// A collection of arguments for invoking getPublishers.
type GetPublishersOutputArgs struct {
	// The unique identifier for the compartment.
	CompartmentId pulumi.StringPtrInput         `pulumi:"compartmentId"`
	Filters       GetPublishersFilterArrayInput `pulumi:"filters"`
	// Limit results to just this publisher.
	PublisherId pulumi.StringPtrInput `pulumi:"publisherId"`
}

func (GetPublishersOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetPublishersArgs)(nil)).Elem()
}

// A collection of values returned by getPublishers.
type GetPublishersResultOutput struct{ *pulumi.OutputState }

func (GetPublishersResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetPublishersResult)(nil)).Elem()
}

func (o GetPublishersResultOutput) ToGetPublishersResultOutput() GetPublishersResultOutput {
	return o
}

func (o GetPublishersResultOutput) ToGetPublishersResultOutputWithContext(ctx context.Context) GetPublishersResultOutput {
	return o
}

func (o GetPublishersResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetPublishersResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

func (o GetPublishersResultOutput) Filters() GetPublishersFilterArrayOutput {
	return o.ApplyT(func(v GetPublishersResult) []GetPublishersFilter { return v.Filters }).(GetPublishersFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetPublishersResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetPublishersResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetPublishersResultOutput) PublisherId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetPublishersResult) *string { return v.PublisherId }).(pulumi.StringPtrOutput)
}

// The list of publishers.
func (o GetPublishersResultOutput) Publishers() GetPublishersPublisherArrayOutput {
	return o.ApplyT(func(v GetPublishersResult) []GetPublishersPublisher { return v.Publishers }).(GetPublishersPublisherArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetPublishersResultOutput{})
}