// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package ospgateway

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Subscriptions in Oracle Cloud Infrastructure Osp Gateway service.
//
// # Get the subscription data for the compartment
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/OspGateway"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := OspGateway.GetSubscriptions(ctx, &ospgateway.GetSubscriptionsArgs{
//				CompartmentId: _var.Compartment_id,
//				OspHomeRegion: _var.Subscription_osp_home_region,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetSubscriptions(ctx *pulumi.Context, args *GetSubscriptionsArgs, opts ...pulumi.InvokeOption) (*GetSubscriptionsResult, error) {
	var rv GetSubscriptionsResult
	err := ctx.Invoke("oci:OspGateway/getSubscriptions:getSubscriptions", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSubscriptions.
type GetSubscriptionsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string                   `pulumi:"compartmentId"`
	Filters       []GetSubscriptionsFilter `pulumi:"filters"`
	// The home region's public name of the logged in user.
	OspHomeRegion string `pulumi:"ospHomeRegion"`
}

// A collection of values returned by getSubscriptions.
type GetSubscriptionsResult struct {
	CompartmentId string                   `pulumi:"compartmentId"`
	Filters       []GetSubscriptionsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id            string `pulumi:"id"`
	OspHomeRegion string `pulumi:"ospHomeRegion"`
	// The list of subscription_collection.
	SubscriptionCollections []GetSubscriptionsSubscriptionCollection `pulumi:"subscriptionCollections"`
}

func GetSubscriptionsOutput(ctx *pulumi.Context, args GetSubscriptionsOutputArgs, opts ...pulumi.InvokeOption) GetSubscriptionsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetSubscriptionsResult, error) {
			args := v.(GetSubscriptionsArgs)
			r, err := GetSubscriptions(ctx, &args, opts...)
			var s GetSubscriptionsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetSubscriptionsResultOutput)
}

// A collection of arguments for invoking getSubscriptions.
type GetSubscriptionsOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput               `pulumi:"compartmentId"`
	Filters       GetSubscriptionsFilterArrayInput `pulumi:"filters"`
	// The home region's public name of the logged in user.
	OspHomeRegion pulumi.StringInput `pulumi:"ospHomeRegion"`
}

func (GetSubscriptionsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSubscriptionsArgs)(nil)).Elem()
}

// A collection of values returned by getSubscriptions.
type GetSubscriptionsResultOutput struct{ *pulumi.OutputState }

func (GetSubscriptionsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSubscriptionsResult)(nil)).Elem()
}

func (o GetSubscriptionsResultOutput) ToGetSubscriptionsResultOutput() GetSubscriptionsResultOutput {
	return o
}

func (o GetSubscriptionsResultOutput) ToGetSubscriptionsResultOutputWithContext(ctx context.Context) GetSubscriptionsResultOutput {
	return o
}

func (o GetSubscriptionsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSubscriptionsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetSubscriptionsResultOutput) Filters() GetSubscriptionsFilterArrayOutput {
	return o.ApplyT(func(v GetSubscriptionsResult) []GetSubscriptionsFilter { return v.Filters }).(GetSubscriptionsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetSubscriptionsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetSubscriptionsResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetSubscriptionsResultOutput) OspHomeRegion() pulumi.StringOutput {
	return o.ApplyT(func(v GetSubscriptionsResult) string { return v.OspHomeRegion }).(pulumi.StringOutput)
}

// The list of subscription_collection.
func (o GetSubscriptionsResultOutput) SubscriptionCollections() GetSubscriptionsSubscriptionCollectionArrayOutput {
	return o.ApplyT(func(v GetSubscriptionsResult) []GetSubscriptionsSubscriptionCollection {
		return v.SubscriptionCollections
	}).(GetSubscriptionsSubscriptionCollectionArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetSubscriptionsResultOutput{})
}