// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package functions

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Fusion Environment Family Limits And Usage resource in Oracle Cloud Infrastructure Fusion Apps service.
//
// Gets the number of environments (usage) of each type in the fusion environment family, as well as the limit that's allowed to be created based on the group's associated subscriptions.
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
//			_, err := Functions.GetFusionEnvironmentFamilyLimitsAndUsage(ctx, &functions.GetFusionEnvironmentFamilyLimitsAndUsageArgs{
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
func GetFusionEnvironmentFamilyLimitsAndUsage(ctx *pulumi.Context, args *GetFusionEnvironmentFamilyLimitsAndUsageArgs, opts ...pulumi.InvokeOption) (*GetFusionEnvironmentFamilyLimitsAndUsageResult, error) {
	var rv GetFusionEnvironmentFamilyLimitsAndUsageResult
	err := ctx.Invoke("oci:Functions/getFusionEnvironmentFamilyLimitsAndUsage:getFusionEnvironmentFamilyLimitsAndUsage", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getFusionEnvironmentFamilyLimitsAndUsage.
type GetFusionEnvironmentFamilyLimitsAndUsageArgs struct {
	// The unique identifier (OCID) of the FusionEnvironmentFamily.
	FusionEnvironmentFamilyId string `pulumi:"fusionEnvironmentFamilyId"`
}

// A collection of values returned by getFusionEnvironmentFamilyLimitsAndUsage.
type GetFusionEnvironmentFamilyLimitsAndUsageResult struct {
	// The limit and usage for a specific environment type, for example, production, development, or test.
	DevelopmentLimitAndUsages []GetFusionEnvironmentFamilyLimitsAndUsageDevelopmentLimitAndUsage `pulumi:"developmentLimitAndUsages"`
	FusionEnvironmentFamilyId string                                                             `pulumi:"fusionEnvironmentFamilyId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The limit and usage for a specific environment type, for example, production, development, or test.
	ProductionLimitAndUsages []GetFusionEnvironmentFamilyLimitsAndUsageProductionLimitAndUsage `pulumi:"productionLimitAndUsages"`
	// The limit and usage for a specific environment type, for example, production, development, or test.
	TestLimitAndUsages []GetFusionEnvironmentFamilyLimitsAndUsageTestLimitAndUsage `pulumi:"testLimitAndUsages"`
}

func GetFusionEnvironmentFamilyLimitsAndUsageOutput(ctx *pulumi.Context, args GetFusionEnvironmentFamilyLimitsAndUsageOutputArgs, opts ...pulumi.InvokeOption) GetFusionEnvironmentFamilyLimitsAndUsageResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetFusionEnvironmentFamilyLimitsAndUsageResult, error) {
			args := v.(GetFusionEnvironmentFamilyLimitsAndUsageArgs)
			r, err := GetFusionEnvironmentFamilyLimitsAndUsage(ctx, &args, opts...)
			var s GetFusionEnvironmentFamilyLimitsAndUsageResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetFusionEnvironmentFamilyLimitsAndUsageResultOutput)
}

// A collection of arguments for invoking getFusionEnvironmentFamilyLimitsAndUsage.
type GetFusionEnvironmentFamilyLimitsAndUsageOutputArgs struct {
	// The unique identifier (OCID) of the FusionEnvironmentFamily.
	FusionEnvironmentFamilyId pulumi.StringInput `pulumi:"fusionEnvironmentFamilyId"`
}

func (GetFusionEnvironmentFamilyLimitsAndUsageOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFusionEnvironmentFamilyLimitsAndUsageArgs)(nil)).Elem()
}

// A collection of values returned by getFusionEnvironmentFamilyLimitsAndUsage.
type GetFusionEnvironmentFamilyLimitsAndUsageResultOutput struct{ *pulumi.OutputState }

func (GetFusionEnvironmentFamilyLimitsAndUsageResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFusionEnvironmentFamilyLimitsAndUsageResult)(nil)).Elem()
}

func (o GetFusionEnvironmentFamilyLimitsAndUsageResultOutput) ToGetFusionEnvironmentFamilyLimitsAndUsageResultOutput() GetFusionEnvironmentFamilyLimitsAndUsageResultOutput {
	return o
}

func (o GetFusionEnvironmentFamilyLimitsAndUsageResultOutput) ToGetFusionEnvironmentFamilyLimitsAndUsageResultOutputWithContext(ctx context.Context) GetFusionEnvironmentFamilyLimitsAndUsageResultOutput {
	return o
}

// The limit and usage for a specific environment type, for example, production, development, or test.
func (o GetFusionEnvironmentFamilyLimitsAndUsageResultOutput) DevelopmentLimitAndUsages() GetFusionEnvironmentFamilyLimitsAndUsageDevelopmentLimitAndUsageArrayOutput {
	return o.ApplyT(func(v GetFusionEnvironmentFamilyLimitsAndUsageResult) []GetFusionEnvironmentFamilyLimitsAndUsageDevelopmentLimitAndUsage {
		return v.DevelopmentLimitAndUsages
	}).(GetFusionEnvironmentFamilyLimitsAndUsageDevelopmentLimitAndUsageArrayOutput)
}

func (o GetFusionEnvironmentFamilyLimitsAndUsageResultOutput) FusionEnvironmentFamilyId() pulumi.StringOutput {
	return o.ApplyT(func(v GetFusionEnvironmentFamilyLimitsAndUsageResult) string { return v.FusionEnvironmentFamilyId }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetFusionEnvironmentFamilyLimitsAndUsageResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetFusionEnvironmentFamilyLimitsAndUsageResult) string { return v.Id }).(pulumi.StringOutput)
}

// The limit and usage for a specific environment type, for example, production, development, or test.
func (o GetFusionEnvironmentFamilyLimitsAndUsageResultOutput) ProductionLimitAndUsages() GetFusionEnvironmentFamilyLimitsAndUsageProductionLimitAndUsageArrayOutput {
	return o.ApplyT(func(v GetFusionEnvironmentFamilyLimitsAndUsageResult) []GetFusionEnvironmentFamilyLimitsAndUsageProductionLimitAndUsage {
		return v.ProductionLimitAndUsages
	}).(GetFusionEnvironmentFamilyLimitsAndUsageProductionLimitAndUsageArrayOutput)
}

// The limit and usage for a specific environment type, for example, production, development, or test.
func (o GetFusionEnvironmentFamilyLimitsAndUsageResultOutput) TestLimitAndUsages() GetFusionEnvironmentFamilyLimitsAndUsageTestLimitAndUsageArrayOutput {
	return o.ApplyT(func(v GetFusionEnvironmentFamilyLimitsAndUsageResult) []GetFusionEnvironmentFamilyLimitsAndUsageTestLimitAndUsage {
		return v.TestLimitAndUsages
	}).(GetFusionEnvironmentFamilyLimitsAndUsageTestLimitAndUsageArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetFusionEnvironmentFamilyLimitsAndUsageResultOutput{})
}