// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package usageproxy

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Subscription Redemption resource in Oracle Cloud Infrastructure Usage Proxy service.
//
// Returns the list of redemption for the subscription ID.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/UsageProxy"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := UsageProxy.GetSubscriptionRedemption(ctx, &usageproxy.GetSubscriptionRedemptionArgs{
//				SubscriptionId:                   oci_onesubscription_subscription.Test_subscription.Id,
//				TenancyId:                        oci_identity_tenancy.Test_tenancy.Id,
//				TimeRedeemedGreaterThanOrEqualTo: pulumi.StringRef(_var.Subscription_redemption_time_redeemed_greater_than_or_equal_to),
//				TimeRedeemedLessThan:             pulumi.StringRef(_var.Subscription_redemption_time_redeemed_less_than),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetSubscriptionRedemption(ctx *pulumi.Context, args *GetSubscriptionRedemptionArgs, opts ...pulumi.InvokeOption) (*GetSubscriptionRedemptionResult, error) {
	var rv GetSubscriptionRedemptionResult
	err := ctx.Invoke("oci:UsageProxy/getSubscriptionRedemption:getSubscriptionRedemption", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSubscriptionRedemption.
type GetSubscriptionRedemptionArgs struct {
	// The subscription ID for which rewards information is requested for.
	SubscriptionId string `pulumi:"subscriptionId"`
	// The OCID of the tenancy.
	TenancyId string `pulumi:"tenancyId"`
	// The starting redeemed date filter for the redemption history.
	TimeRedeemedGreaterThanOrEqualTo *string `pulumi:"timeRedeemedGreaterThanOrEqualTo"`
	// The ending redeemed date filter for the redemption history.
	TimeRedeemedLessThan *string `pulumi:"timeRedeemedLessThan"`
}

// A collection of values returned by getSubscriptionRedemption.
type GetSubscriptionRedemptionResult struct {
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of redemption summary.
	Items                            []GetSubscriptionRedemptionItem `pulumi:"items"`
	SubscriptionId                   string                          `pulumi:"subscriptionId"`
	TenancyId                        string                          `pulumi:"tenancyId"`
	TimeRedeemedGreaterThanOrEqualTo *string                         `pulumi:"timeRedeemedGreaterThanOrEqualTo"`
	TimeRedeemedLessThan             *string                         `pulumi:"timeRedeemedLessThan"`
}

func GetSubscriptionRedemptionOutput(ctx *pulumi.Context, args GetSubscriptionRedemptionOutputArgs, opts ...pulumi.InvokeOption) GetSubscriptionRedemptionResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetSubscriptionRedemptionResult, error) {
			args := v.(GetSubscriptionRedemptionArgs)
			r, err := GetSubscriptionRedemption(ctx, &args, opts...)
			var s GetSubscriptionRedemptionResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetSubscriptionRedemptionResultOutput)
}

// A collection of arguments for invoking getSubscriptionRedemption.
type GetSubscriptionRedemptionOutputArgs struct {
	// The subscription ID for which rewards information is requested for.
	SubscriptionId pulumi.StringInput `pulumi:"subscriptionId"`
	// The OCID of the tenancy.
	TenancyId pulumi.StringInput `pulumi:"tenancyId"`
	// The starting redeemed date filter for the redemption history.
	TimeRedeemedGreaterThanOrEqualTo pulumi.StringPtrInput `pulumi:"timeRedeemedGreaterThanOrEqualTo"`
	// The ending redeemed date filter for the redemption history.
	TimeRedeemedLessThan pulumi.StringPtrInput `pulumi:"timeRedeemedLessThan"`
}

func (GetSubscriptionRedemptionOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSubscriptionRedemptionArgs)(nil)).Elem()
}

// A collection of values returned by getSubscriptionRedemption.
type GetSubscriptionRedemptionResultOutput struct{ *pulumi.OutputState }

func (GetSubscriptionRedemptionResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSubscriptionRedemptionResult)(nil)).Elem()
}

func (o GetSubscriptionRedemptionResultOutput) ToGetSubscriptionRedemptionResultOutput() GetSubscriptionRedemptionResultOutput {
	return o
}

func (o GetSubscriptionRedemptionResultOutput) ToGetSubscriptionRedemptionResultOutputWithContext(ctx context.Context) GetSubscriptionRedemptionResultOutput {
	return o
}

// The provider-assigned unique ID for this managed resource.
func (o GetSubscriptionRedemptionResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetSubscriptionRedemptionResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of redemption summary.
func (o GetSubscriptionRedemptionResultOutput) Items() GetSubscriptionRedemptionItemArrayOutput {
	return o.ApplyT(func(v GetSubscriptionRedemptionResult) []GetSubscriptionRedemptionItem { return v.Items }).(GetSubscriptionRedemptionItemArrayOutput)
}

func (o GetSubscriptionRedemptionResultOutput) SubscriptionId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSubscriptionRedemptionResult) string { return v.SubscriptionId }).(pulumi.StringOutput)
}

func (o GetSubscriptionRedemptionResultOutput) TenancyId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSubscriptionRedemptionResult) string { return v.TenancyId }).(pulumi.StringOutput)
}

func (o GetSubscriptionRedemptionResultOutput) TimeRedeemedGreaterThanOrEqualTo() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSubscriptionRedemptionResult) *string { return v.TimeRedeemedGreaterThanOrEqualTo }).(pulumi.StringPtrOutput)
}

func (o GetSubscriptionRedemptionResultOutput) TimeRedeemedLessThan() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSubscriptionRedemptionResult) *string { return v.TimeRedeemedLessThan }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetSubscriptionRedemptionResultOutput{})
}