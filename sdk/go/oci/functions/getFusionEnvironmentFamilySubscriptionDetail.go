// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package functions

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Fusion Environment Family Subscription Detail resource in Oracle Cloud Infrastructure Fusion Apps service.
//
// Gets the subscription details of an fusion environment family.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Functions"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Functions.GetFusionEnvironmentFamilySubscriptionDetail(ctx, &functions.GetFusionEnvironmentFamilySubscriptionDetailArgs{
//				FusionEnvironmentFamilyId: oci_fusion_apps_fusion_environment_family.Test_fusion_environment_family.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetFusionEnvironmentFamilySubscriptionDetail(ctx *pulumi.Context, args *GetFusionEnvironmentFamilySubscriptionDetailArgs, opts ...pulumi.InvokeOption) (*GetFusionEnvironmentFamilySubscriptionDetailResult, error) {
	var rv GetFusionEnvironmentFamilySubscriptionDetailResult
	err := ctx.Invoke("oci:Functions/getFusionEnvironmentFamilySubscriptionDetail:getFusionEnvironmentFamilySubscriptionDetail", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getFusionEnvironmentFamilySubscriptionDetail.
type GetFusionEnvironmentFamilySubscriptionDetailArgs struct {
	// The unique identifier (OCID) of the FusionEnvironmentFamily.
	FusionEnvironmentFamilyId string `pulumi:"fusionEnvironmentFamilyId"`
}

// A collection of values returned by getFusionEnvironmentFamilySubscriptionDetail.
type GetFusionEnvironmentFamilySubscriptionDetailResult struct {
	FusionEnvironmentFamilyId string `pulumi:"fusionEnvironmentFamilyId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// List of subscriptions.
	Subscriptions []GetFusionEnvironmentFamilySubscriptionDetailSubscription `pulumi:"subscriptions"`
}

func GetFusionEnvironmentFamilySubscriptionDetailOutput(ctx *pulumi.Context, args GetFusionEnvironmentFamilySubscriptionDetailOutputArgs, opts ...pulumi.InvokeOption) GetFusionEnvironmentFamilySubscriptionDetailResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetFusionEnvironmentFamilySubscriptionDetailResult, error) {
			args := v.(GetFusionEnvironmentFamilySubscriptionDetailArgs)
			r, err := GetFusionEnvironmentFamilySubscriptionDetail(ctx, &args, opts...)
			var s GetFusionEnvironmentFamilySubscriptionDetailResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetFusionEnvironmentFamilySubscriptionDetailResultOutput)
}

// A collection of arguments for invoking getFusionEnvironmentFamilySubscriptionDetail.
type GetFusionEnvironmentFamilySubscriptionDetailOutputArgs struct {
	// The unique identifier (OCID) of the FusionEnvironmentFamily.
	FusionEnvironmentFamilyId pulumi.StringInput `pulumi:"fusionEnvironmentFamilyId"`
}

func (GetFusionEnvironmentFamilySubscriptionDetailOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFusionEnvironmentFamilySubscriptionDetailArgs)(nil)).Elem()
}

// A collection of values returned by getFusionEnvironmentFamilySubscriptionDetail.
type GetFusionEnvironmentFamilySubscriptionDetailResultOutput struct{ *pulumi.OutputState }

func (GetFusionEnvironmentFamilySubscriptionDetailResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFusionEnvironmentFamilySubscriptionDetailResult)(nil)).Elem()
}

func (o GetFusionEnvironmentFamilySubscriptionDetailResultOutput) ToGetFusionEnvironmentFamilySubscriptionDetailResultOutput() GetFusionEnvironmentFamilySubscriptionDetailResultOutput {
	return o
}

func (o GetFusionEnvironmentFamilySubscriptionDetailResultOutput) ToGetFusionEnvironmentFamilySubscriptionDetailResultOutputWithContext(ctx context.Context) GetFusionEnvironmentFamilySubscriptionDetailResultOutput {
	return o
}

func (o GetFusionEnvironmentFamilySubscriptionDetailResultOutput) FusionEnvironmentFamilyId() pulumi.StringOutput {
	return o.ApplyT(func(v GetFusionEnvironmentFamilySubscriptionDetailResult) string { return v.FusionEnvironmentFamilyId }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetFusionEnvironmentFamilySubscriptionDetailResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetFusionEnvironmentFamilySubscriptionDetailResult) string { return v.Id }).(pulumi.StringOutput)
}

// List of subscriptions.
func (o GetFusionEnvironmentFamilySubscriptionDetailResultOutput) Subscriptions() GetFusionEnvironmentFamilySubscriptionDetailSubscriptionArrayOutput {
	return o.ApplyT(func(v GetFusionEnvironmentFamilySubscriptionDetailResult) []GetFusionEnvironmentFamilySubscriptionDetailSubscription {
		return v.Subscriptions
	}).(GetFusionEnvironmentFamilySubscriptionDetailSubscriptionArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetFusionEnvironmentFamilySubscriptionDetailResultOutput{})
}