// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package cloudguard

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Responder Recipe resource in Oracle Cloud Infrastructure Cloud Guard service.
//
// Returns a responder recipe (ResponderRecipe resource) identified by responderRecipeId.
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
//			_, err := cloudguard.GetResponderRecipe(ctx, &cloudguard.GetResponderRecipeArgs{
//				ResponderRecipeId: testResponderRecipeOciCloudGuardResponderRecipe.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupResponderRecipe(ctx *pulumi.Context, args *LookupResponderRecipeArgs, opts ...pulumi.InvokeOption) (*LookupResponderRecipeResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupResponderRecipeResult
	err := ctx.Invoke("oci:CloudGuard/getResponderRecipe:getResponderRecipe", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getResponderRecipe.
type LookupResponderRecipeArgs struct {
	// OCID of the responder recipe.
	ResponderRecipeId string `pulumi:"responderRecipeId"`
}

// A collection of values returned by getResponderRecipe.
type LookupResponderRecipeResult struct {
	// Compartment OCID
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Responder rule description
	Description string `pulumi:"description"`
	// Responder rule display name
	DisplayName string `pulumi:"displayName"`
	// List of currently enabled responder rules for the responder type, for recipe after applying defaults
	EffectiveResponderRules []GetResponderRecipeEffectiveResponderRule `pulumi:"effectiveResponderRules"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// Unique identifier for the responder recip
	Id string `pulumi:"id"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// Owner of responder recipe
	Owner             string `pulumi:"owner"`
	ResponderRecipeId string `pulumi:"responderRecipeId"`
	// List of responder rules associated with the recipe
	ResponderRules []GetResponderRecipeResponderRule `pulumi:"responderRules"`
	// The unique identifier of the source responder recipe
	SourceResponderRecipeId string `pulumi:"sourceResponderRecipeId"`
	// The current lifecycle state of the example
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The date and time the responder recipe was created. Format defined by RFC3339.
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the responder recipe was last updated. Format defined by RFC3339.
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupResponderRecipeOutput(ctx *pulumi.Context, args LookupResponderRecipeOutputArgs, opts ...pulumi.InvokeOption) LookupResponderRecipeResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupResponderRecipeResultOutput, error) {
			args := v.(LookupResponderRecipeArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:CloudGuard/getResponderRecipe:getResponderRecipe", args, LookupResponderRecipeResultOutput{}, options).(LookupResponderRecipeResultOutput), nil
		}).(LookupResponderRecipeResultOutput)
}

// A collection of arguments for invoking getResponderRecipe.
type LookupResponderRecipeOutputArgs struct {
	// OCID of the responder recipe.
	ResponderRecipeId pulumi.StringInput `pulumi:"responderRecipeId"`
}

func (LookupResponderRecipeOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupResponderRecipeArgs)(nil)).Elem()
}

// A collection of values returned by getResponderRecipe.
type LookupResponderRecipeResultOutput struct{ *pulumi.OutputState }

func (LookupResponderRecipeResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupResponderRecipeResult)(nil)).Elem()
}

func (o LookupResponderRecipeResultOutput) ToLookupResponderRecipeResultOutput() LookupResponderRecipeResultOutput {
	return o
}

func (o LookupResponderRecipeResultOutput) ToLookupResponderRecipeResultOutputWithContext(ctx context.Context) LookupResponderRecipeResultOutput {
	return o
}

// Compartment OCID
func (o LookupResponderRecipeResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResponderRecipeResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupResponderRecipeResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupResponderRecipeResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// Responder rule description
func (o LookupResponderRecipeResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResponderRecipeResult) string { return v.Description }).(pulumi.StringOutput)
}

// Responder rule display name
func (o LookupResponderRecipeResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResponderRecipeResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// List of currently enabled responder rules for the responder type, for recipe after applying defaults
func (o LookupResponderRecipeResultOutput) EffectiveResponderRules() GetResponderRecipeEffectiveResponderRuleArrayOutput {
	return o.ApplyT(func(v LookupResponderRecipeResult) []GetResponderRecipeEffectiveResponderRule {
		return v.EffectiveResponderRules
	}).(GetResponderRecipeEffectiveResponderRuleArrayOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupResponderRecipeResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupResponderRecipeResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// Unique identifier for the responder recip
func (o LookupResponderRecipeResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResponderRecipeResult) string { return v.Id }).(pulumi.StringOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
func (o LookupResponderRecipeResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResponderRecipeResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Owner of responder recipe
func (o LookupResponderRecipeResultOutput) Owner() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResponderRecipeResult) string { return v.Owner }).(pulumi.StringOutput)
}

func (o LookupResponderRecipeResultOutput) ResponderRecipeId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResponderRecipeResult) string { return v.ResponderRecipeId }).(pulumi.StringOutput)
}

// List of responder rules associated with the recipe
func (o LookupResponderRecipeResultOutput) ResponderRules() GetResponderRecipeResponderRuleArrayOutput {
	return o.ApplyT(func(v LookupResponderRecipeResult) []GetResponderRecipeResponderRule { return v.ResponderRules }).(GetResponderRecipeResponderRuleArrayOutput)
}

// The unique identifier of the source responder recipe
func (o LookupResponderRecipeResultOutput) SourceResponderRecipeId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResponderRecipeResult) string { return v.SourceResponderRecipeId }).(pulumi.StringOutput)
}

// The current lifecycle state of the example
func (o LookupResponderRecipeResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResponderRecipeResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupResponderRecipeResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupResponderRecipeResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The date and time the responder recipe was created. Format defined by RFC3339.
func (o LookupResponderRecipeResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResponderRecipeResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the responder recipe was last updated. Format defined by RFC3339.
func (o LookupResponderRecipeResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResponderRecipeResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupResponderRecipeResultOutput{})
}
