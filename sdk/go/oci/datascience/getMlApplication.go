// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datascience

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Ml Application resource in Oracle Cloud Infrastructure Data Science service.
//
// # Gets a MlApplication by identifier
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/datascience"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := datascience.GetMlApplication(ctx, &datascience.GetMlApplicationArgs{
//				MlApplicationId: testMlApplicationOciDatascienceMlApplication.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupMlApplication(ctx *pulumi.Context, args *LookupMlApplicationArgs, opts ...pulumi.InvokeOption) (*LookupMlApplicationResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupMlApplicationResult
	err := ctx.Invoke("oci:DataScience/getMlApplication:getMlApplication", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMlApplication.
type LookupMlApplicationArgs struct {
	// unique MlApplication identifier
	MlApplicationId string `pulumi:"mlApplicationId"`
}

// A collection of values returned by getMlApplication.
type LookupMlApplicationResult struct {
	// The OCID of the compartment where the MlApplication is created.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Optional description of the ML Application
	Description string `pulumi:"description"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The OCID of the MlApplication. Unique identifier that is immutable after creation.
	Id string `pulumi:"id"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	MlApplicationId  string `pulumi:"mlApplicationId"`
	// The name of MlApplication. It is unique in a given tenancy.
	Name string `pulumi:"name"`
	// The current state of the MlApplication.
	State string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// Creation time of MlApplication in the format defined by RFC 3339.
	TimeCreated string `pulumi:"timeCreated"`
	// Time of last MlApplication update in the format defined by RFC 3339.
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupMlApplicationOutput(ctx *pulumi.Context, args LookupMlApplicationOutputArgs, opts ...pulumi.InvokeOption) LookupMlApplicationResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupMlApplicationResultOutput, error) {
			args := v.(LookupMlApplicationArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DataScience/getMlApplication:getMlApplication", args, LookupMlApplicationResultOutput{}, options).(LookupMlApplicationResultOutput), nil
		}).(LookupMlApplicationResultOutput)
}

// A collection of arguments for invoking getMlApplication.
type LookupMlApplicationOutputArgs struct {
	// unique MlApplication identifier
	MlApplicationId pulumi.StringInput `pulumi:"mlApplicationId"`
}

func (LookupMlApplicationOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupMlApplicationArgs)(nil)).Elem()
}

// A collection of values returned by getMlApplication.
type LookupMlApplicationResultOutput struct{ *pulumi.OutputState }

func (LookupMlApplicationResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupMlApplicationResult)(nil)).Elem()
}

func (o LookupMlApplicationResultOutput) ToLookupMlApplicationResultOutput() LookupMlApplicationResultOutput {
	return o
}

func (o LookupMlApplicationResultOutput) ToLookupMlApplicationResultOutputWithContext(ctx context.Context) LookupMlApplicationResultOutput {
	return o
}

// The OCID of the compartment where the MlApplication is created.
func (o LookupMlApplicationResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMlApplicationResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o LookupMlApplicationResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupMlApplicationResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// Optional description of the ML Application
func (o LookupMlApplicationResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMlApplicationResult) string { return v.Description }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o LookupMlApplicationResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupMlApplicationResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The OCID of the MlApplication. Unique identifier that is immutable after creation.
func (o LookupMlApplicationResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMlApplicationResult) string { return v.Id }).(pulumi.StringOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
func (o LookupMlApplicationResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMlApplicationResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

func (o LookupMlApplicationResultOutput) MlApplicationId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMlApplicationResult) string { return v.MlApplicationId }).(pulumi.StringOutput)
}

// The name of MlApplication. It is unique in a given tenancy.
func (o LookupMlApplicationResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMlApplicationResult) string { return v.Name }).(pulumi.StringOutput)
}

// The current state of the MlApplication.
func (o LookupMlApplicationResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMlApplicationResult) string { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupMlApplicationResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupMlApplicationResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// Creation time of MlApplication in the format defined by RFC 3339.
func (o LookupMlApplicationResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMlApplicationResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// Time of last MlApplication update in the format defined by RFC 3339.
func (o LookupMlApplicationResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMlApplicationResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupMlApplicationResultOutput{})
}
