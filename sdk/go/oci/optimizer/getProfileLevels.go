// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package optimizer

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Profile Levels in Oracle Cloud Infrastructure Optimizer service.
//
// Lists the existing profile levels.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Optimizer"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Optimizer.GetProfileLevels(ctx, &optimizer.GetProfileLevelsArgs{
//				CompartmentId:          _var.Compartment_id,
//				CompartmentIdInSubtree: _var.Profile_level_compartment_id_in_subtree,
//				Name:                   pulumi.StringRef(_var.Profile_level_name),
//				RecommendationName:     pulumi.StringRef(oci_optimizer_recommendation.Test_recommendation.Name),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetProfileLevels(ctx *pulumi.Context, args *GetProfileLevelsArgs, opts ...pulumi.InvokeOption) (*GetProfileLevelsResult, error) {
	var rv GetProfileLevelsResult
	err := ctx.Invoke("oci:Optimizer/getProfileLevels:getProfileLevels", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getProfileLevels.
type GetProfileLevelsArgs struct {
	// The OCID of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
	CompartmentIdInSubtree bool                     `pulumi:"compartmentIdInSubtree"`
	Filters                []GetProfileLevelsFilter `pulumi:"filters"`
	// Optional. A filter that returns results that match the name specified.
	Name *string `pulumi:"name"`
	// Optional. A filter that returns results that match the recommendation name specified.
	RecommendationName *string `pulumi:"recommendationName"`
}

// A collection of values returned by getProfileLevels.
type GetProfileLevelsResult struct {
	CompartmentId          string                   `pulumi:"compartmentId"`
	CompartmentIdInSubtree bool                     `pulumi:"compartmentIdInSubtree"`
	Filters                []GetProfileLevelsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// A unique name for the profile level.
	Name *string `pulumi:"name"`
	// The list of profile_level_collection.
	ProfileLevelCollections []GetProfileLevelsProfileLevelCollection `pulumi:"profileLevelCollections"`
	// The name of the recommendation this profile level applies to.
	RecommendationName *string `pulumi:"recommendationName"`
}

func GetProfileLevelsOutput(ctx *pulumi.Context, args GetProfileLevelsOutputArgs, opts ...pulumi.InvokeOption) GetProfileLevelsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetProfileLevelsResult, error) {
			args := v.(GetProfileLevelsArgs)
			r, err := GetProfileLevels(ctx, &args, opts...)
			var s GetProfileLevelsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetProfileLevelsResultOutput)
}

// A collection of arguments for invoking getProfileLevels.
type GetProfileLevelsOutputArgs struct {
	// The OCID of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
	CompartmentIdInSubtree pulumi.BoolInput                 `pulumi:"compartmentIdInSubtree"`
	Filters                GetProfileLevelsFilterArrayInput `pulumi:"filters"`
	// Optional. A filter that returns results that match the name specified.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// Optional. A filter that returns results that match the recommendation name specified.
	RecommendationName pulumi.StringPtrInput `pulumi:"recommendationName"`
}

func (GetProfileLevelsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetProfileLevelsArgs)(nil)).Elem()
}

// A collection of values returned by getProfileLevels.
type GetProfileLevelsResultOutput struct{ *pulumi.OutputState }

func (GetProfileLevelsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetProfileLevelsResult)(nil)).Elem()
}

func (o GetProfileLevelsResultOutput) ToGetProfileLevelsResultOutput() GetProfileLevelsResultOutput {
	return o
}

func (o GetProfileLevelsResultOutput) ToGetProfileLevelsResultOutputWithContext(ctx context.Context) GetProfileLevelsResultOutput {
	return o
}

func (o GetProfileLevelsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetProfileLevelsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetProfileLevelsResultOutput) CompartmentIdInSubtree() pulumi.BoolOutput {
	return o.ApplyT(func(v GetProfileLevelsResult) bool { return v.CompartmentIdInSubtree }).(pulumi.BoolOutput)
}

func (o GetProfileLevelsResultOutput) Filters() GetProfileLevelsFilterArrayOutput {
	return o.ApplyT(func(v GetProfileLevelsResult) []GetProfileLevelsFilter { return v.Filters }).(GetProfileLevelsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetProfileLevelsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetProfileLevelsResult) string { return v.Id }).(pulumi.StringOutput)
}

// A unique name for the profile level.
func (o GetProfileLevelsResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetProfileLevelsResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The list of profile_level_collection.
func (o GetProfileLevelsResultOutput) ProfileLevelCollections() GetProfileLevelsProfileLevelCollectionArrayOutput {
	return o.ApplyT(func(v GetProfileLevelsResult) []GetProfileLevelsProfileLevelCollection {
		return v.ProfileLevelCollections
	}).(GetProfileLevelsProfileLevelCollectionArrayOutput)
}

// The name of the recommendation this profile level applies to.
func (o GetProfileLevelsResultOutput) RecommendationName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetProfileLevelsResult) *string { return v.RecommendationName }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetProfileLevelsResultOutput{})
}