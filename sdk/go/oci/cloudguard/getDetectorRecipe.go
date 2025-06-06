// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package cloudguard

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Detector Recipe resource in Oracle Cloud Infrastructure Cloud Guard service.
//
// Returns a detector recipe (DetectorRecipe resource) identified by detectorRecipeId.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/cloudguard"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := cloudguard.GetDetectorRecipe(ctx, &cloudguard.GetDetectorRecipeArgs{
//				DetectorRecipeId: testDetectorRecipeOciCloudGuardDetectorRecipe.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupDetectorRecipe(ctx *pulumi.Context, args *LookupDetectorRecipeArgs, opts ...pulumi.InvokeOption) (*LookupDetectorRecipeResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupDetectorRecipeResult
	err := ctx.Invoke("oci:CloudGuard/getDetectorRecipe:getDetectorRecipe", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDetectorRecipe.
type LookupDetectorRecipeArgs struct {
	// Detector recipe OCID
	DetectorRecipeId string `pulumi:"detectorRecipeId"`
}

// A collection of values returned by getDetectorRecipe.
type LookupDetectorRecipeResult struct {
	// Compartment OCID of detector recipe
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Description for detector recipe detector rule
	Description string `pulumi:"description"`
	// Detector recipe for the rule
	Detector         string `pulumi:"detector"`
	DetectorRecipeId string `pulumi:"detectorRecipeId"`
	// Recipe type ( STANDARD, ENTERPRISE )
	DetectorRecipeType string `pulumi:"detectorRecipeType"`
	// List of detector rules for the detector type for recipe - user input
	DetectorRules []GetDetectorRecipeDetectorRule `pulumi:"detectorRules"`
	// Display name of the entity
	DisplayName string `pulumi:"displayName"`
	// List of effective detector rules for the detector type for recipe after applying defaults
	EffectiveDetectorRules []GetDetectorRecipeEffectiveDetectorRule `pulumi:"effectiveDetectorRules"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// OCID for detector recipe
	Id string `pulumi:"id"`
	// Owner of detector recipe
	Owner string `pulumi:"owner"`
	// Recipe OCID of the source recipe to be cloned
	SourceDetectorRecipeId string `pulumi:"sourceDetectorRecipeId"`
	// The current lifecycle state of the resource
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// List of target IDs to which the recipe is attached
	TargetIds []string `pulumi:"targetIds"`
	// The date and time the detector recipe was created Format defined by RFC3339.
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the detector recipe was last updated Format defined by RFC3339.
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupDetectorRecipeOutput(ctx *pulumi.Context, args LookupDetectorRecipeOutputArgs, opts ...pulumi.InvokeOption) LookupDetectorRecipeResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupDetectorRecipeResultOutput, error) {
			args := v.(LookupDetectorRecipeArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:CloudGuard/getDetectorRecipe:getDetectorRecipe", args, LookupDetectorRecipeResultOutput{}, options).(LookupDetectorRecipeResultOutput), nil
		}).(LookupDetectorRecipeResultOutput)
}

// A collection of arguments for invoking getDetectorRecipe.
type LookupDetectorRecipeOutputArgs struct {
	// Detector recipe OCID
	DetectorRecipeId pulumi.StringInput `pulumi:"detectorRecipeId"`
}

func (LookupDetectorRecipeOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDetectorRecipeArgs)(nil)).Elem()
}

// A collection of values returned by getDetectorRecipe.
type LookupDetectorRecipeResultOutput struct{ *pulumi.OutputState }

func (LookupDetectorRecipeResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDetectorRecipeResult)(nil)).Elem()
}

func (o LookupDetectorRecipeResultOutput) ToLookupDetectorRecipeResultOutput() LookupDetectorRecipeResultOutput {
	return o
}

func (o LookupDetectorRecipeResultOutput) ToLookupDetectorRecipeResultOutputWithContext(ctx context.Context) LookupDetectorRecipeResultOutput {
	return o
}

// Compartment OCID of detector recipe
func (o LookupDetectorRecipeResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDetectorRecipeResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupDetectorRecipeResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupDetectorRecipeResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// Description for detector recipe detector rule
func (o LookupDetectorRecipeResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDetectorRecipeResult) string { return v.Description }).(pulumi.StringOutput)
}

// Detector recipe for the rule
func (o LookupDetectorRecipeResultOutput) Detector() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDetectorRecipeResult) string { return v.Detector }).(pulumi.StringOutput)
}

func (o LookupDetectorRecipeResultOutput) DetectorRecipeId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDetectorRecipeResult) string { return v.DetectorRecipeId }).(pulumi.StringOutput)
}

// Recipe type ( STANDARD, ENTERPRISE )
func (o LookupDetectorRecipeResultOutput) DetectorRecipeType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDetectorRecipeResult) string { return v.DetectorRecipeType }).(pulumi.StringOutput)
}

// List of detector rules for the detector type for recipe - user input
func (o LookupDetectorRecipeResultOutput) DetectorRules() GetDetectorRecipeDetectorRuleArrayOutput {
	return o.ApplyT(func(v LookupDetectorRecipeResult) []GetDetectorRecipeDetectorRule { return v.DetectorRules }).(GetDetectorRecipeDetectorRuleArrayOutput)
}

// Display name of the entity
func (o LookupDetectorRecipeResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDetectorRecipeResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// List of effective detector rules for the detector type for recipe after applying defaults
func (o LookupDetectorRecipeResultOutput) EffectiveDetectorRules() GetDetectorRecipeEffectiveDetectorRuleArrayOutput {
	return o.ApplyT(func(v LookupDetectorRecipeResult) []GetDetectorRecipeEffectiveDetectorRule {
		return v.EffectiveDetectorRules
	}).(GetDetectorRecipeEffectiveDetectorRuleArrayOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupDetectorRecipeResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupDetectorRecipeResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// OCID for detector recipe
func (o LookupDetectorRecipeResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDetectorRecipeResult) string { return v.Id }).(pulumi.StringOutput)
}

// Owner of detector recipe
func (o LookupDetectorRecipeResultOutput) Owner() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDetectorRecipeResult) string { return v.Owner }).(pulumi.StringOutput)
}

// Recipe OCID of the source recipe to be cloned
func (o LookupDetectorRecipeResultOutput) SourceDetectorRecipeId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDetectorRecipeResult) string { return v.SourceDetectorRecipeId }).(pulumi.StringOutput)
}

// The current lifecycle state of the resource
func (o LookupDetectorRecipeResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDetectorRecipeResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupDetectorRecipeResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupDetectorRecipeResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// List of target IDs to which the recipe is attached
func (o LookupDetectorRecipeResultOutput) TargetIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupDetectorRecipeResult) []string { return v.TargetIds }).(pulumi.StringArrayOutput)
}

// The date and time the detector recipe was created Format defined by RFC3339.
func (o LookupDetectorRecipeResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDetectorRecipeResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the detector recipe was last updated Format defined by RFC3339.
func (o LookupDetectorRecipeResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDetectorRecipeResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupDetectorRecipeResultOutput{})
}
