// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package adm

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

// This data source provides the list of Remediation Runs in Oracle Cloud Infrastructure Adm service.
//
// Returns a list of remediation runs contained by a compartment.
// The query parameter `compartmentId` is required unless the query parameter `id` is specified.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Adm"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Adm.GetRemediationRuns(ctx, &adm.GetRemediationRunsArgs{
//				CompartmentId:       pulumi.StringRef(_var.Compartment_id),
//				DisplayName:         pulumi.StringRef(_var.Remediation_run_display_name),
//				Id:                  pulumi.StringRef(_var.Remediation_run_id),
//				RemediationRecipeId: pulumi.StringRef(oci_adm_remediation_recipe.Test_remediation_recipe.Id),
//				State:               pulumi.StringRef(_var.Remediation_run_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetRemediationRuns(ctx *pulumi.Context, args *GetRemediationRunsArgs, opts ...pulumi.InvokeOption) (*GetRemediationRunsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetRemediationRunsResult
	err := ctx.Invoke("oci:Adm/getRemediationRuns:getRemediationRuns", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getRemediationRuns.
type GetRemediationRunsArgs struct {
	// A filter to return only resources that belong to the specified compartment identifier. Required only if the id query param is not specified.
	CompartmentId *string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName *string                    `pulumi:"displayName"`
	Filters     []GetRemediationRunsFilter `pulumi:"filters"`
	// A filter to return only resources that match the specified identifier. Required only if the compartmentId query parameter is not specified.
	Id *string `pulumi:"id"`
	// A filter to return only resources that match the specified Remediation Recipe identifier.
	RemediationRecipeId *string `pulumi:"remediationRecipeId"`
	// A filter to return only Remediation Runs that match the specified lifecycleState.
	State *string `pulumi:"state"`
}

// A collection of values returned by getRemediationRuns.
type GetRemediationRunsResult struct {
	// The compartment Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation run.
	CompartmentId *string `pulumi:"compartmentId"`
	// The name of the remediation run.
	DisplayName *string                    `pulumi:"displayName"`
	Filters     []GetRemediationRunsFilter `pulumi:"filters"`
	// The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation run.
	Id *string `pulumi:"id"`
	// The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the Remediation Recipe.
	RemediationRecipeId *string `pulumi:"remediationRecipeId"`
	// The list of remediation_run_collection.
	RemediationRunCollections []GetRemediationRunsRemediationRunCollection `pulumi:"remediationRunCollections"`
	// The current lifecycle state of the remediation run.
	State *string `pulumi:"state"`
}

func GetRemediationRunsOutput(ctx *pulumi.Context, args GetRemediationRunsOutputArgs, opts ...pulumi.InvokeOption) GetRemediationRunsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetRemediationRunsResult, error) {
			args := v.(GetRemediationRunsArgs)
			r, err := GetRemediationRuns(ctx, &args, opts...)
			var s GetRemediationRunsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetRemediationRunsResultOutput)
}

// A collection of arguments for invoking getRemediationRuns.
type GetRemediationRunsOutputArgs struct {
	// A filter to return only resources that belong to the specified compartment identifier. Required only if the id query param is not specified.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput              `pulumi:"displayName"`
	Filters     GetRemediationRunsFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources that match the specified identifier. Required only if the compartmentId query parameter is not specified.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// A filter to return only resources that match the specified Remediation Recipe identifier.
	RemediationRecipeId pulumi.StringPtrInput `pulumi:"remediationRecipeId"`
	// A filter to return only Remediation Runs that match the specified lifecycleState.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetRemediationRunsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRemediationRunsArgs)(nil)).Elem()
}

// A collection of values returned by getRemediationRuns.
type GetRemediationRunsResultOutput struct{ *pulumi.OutputState }

func (GetRemediationRunsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRemediationRunsResult)(nil)).Elem()
}

func (o GetRemediationRunsResultOutput) ToGetRemediationRunsResultOutput() GetRemediationRunsResultOutput {
	return o
}

func (o GetRemediationRunsResultOutput) ToGetRemediationRunsResultOutputWithContext(ctx context.Context) GetRemediationRunsResultOutput {
	return o
}

func (o GetRemediationRunsResultOutput) ToOutput(ctx context.Context) pulumix.Output[GetRemediationRunsResult] {
	return pulumix.Output[GetRemediationRunsResult]{
		OutputState: o.OutputState,
	}
}

// The compartment Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation run.
func (o GetRemediationRunsResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRemediationRunsResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// The name of the remediation run.
func (o GetRemediationRunsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRemediationRunsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetRemediationRunsResultOutput) Filters() GetRemediationRunsFilterArrayOutput {
	return o.ApplyT(func(v GetRemediationRunsResult) []GetRemediationRunsFilter { return v.Filters }).(GetRemediationRunsFilterArrayOutput)
}

// The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation run.
func (o GetRemediationRunsResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRemediationRunsResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the Remediation Recipe.
func (o GetRemediationRunsResultOutput) RemediationRecipeId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRemediationRunsResult) *string { return v.RemediationRecipeId }).(pulumi.StringPtrOutput)
}

// The list of remediation_run_collection.
func (o GetRemediationRunsResultOutput) RemediationRunCollections() GetRemediationRunsRemediationRunCollectionArrayOutput {
	return o.ApplyT(func(v GetRemediationRunsResult) []GetRemediationRunsRemediationRunCollection {
		return v.RemediationRunCollections
	}).(GetRemediationRunsRemediationRunCollectionArrayOutput)
}

// The current lifecycle state of the remediation run.
func (o GetRemediationRunsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRemediationRunsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetRemediationRunsResultOutput{})
}